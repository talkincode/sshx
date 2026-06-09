package sshclient

import (
	"fmt"
	"sync"
	"time"

	"github.com/talkincode/sshx/pkg/errutil"
	"github.com/talkincode/sshx/pkg/logger"
	"golang.org/x/crypto/ssh"
)

// ConnectionPool manages SSH connections with pooling and health checks
type ConnectionPool struct {
	mu          sync.RWMutex
	connections map[string]*PooledConnection
	maxIdle     time.Duration // Maximum idle time
	healthCheck time.Duration // Health check interval
	maxRetries  int           // Maximum retry attempts
	retryDelay  time.Duration // Retry delay
}

// PooledConnection represents a pooled SSH connection
type PooledConnection struct {
	client     *ssh.Client
	config     *Config
	lastUsed   time.Time
	mu         sync.Mutex
	inUse      bool
	retryCount int
}

var (
	globalPool     *ConnectionPool
	globalPoolOnce sync.Once
)

// GetConnectionPool returns the global connection pool singleton
func GetConnectionPool() *ConnectionPool {
	globalPoolOnce.Do(func() {
		globalPool = NewConnectionPool()
		// Start background health check and cleanup
		go globalPool.startMaintenance()
	})
	return globalPool
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool() *ConnectionPool {
	return &ConnectionPool{
		connections: make(map[string]*PooledConnection),
		maxIdle:     5 * time.Minute,  // Auto-close after 5 minutes of inactivity
		healthCheck: 30 * time.Second, // Health check every 30 seconds
		maxRetries:  3,                // Maximum 3 retry attempts
		retryDelay:  1 * time.Second,  // 1 second retry delay
	}
}

// GetConnection retrieves or creates a connection from the pool
func (p *ConnectionPool) GetConnection(config *Config) (*ssh.Client, error) {
	key := p.makeKey(config)
	lg := logger.GetLogger()

	p.mu.Lock()
	pooledConn, exists := p.connections[key]

	if exists {
		// Check if connection is still valid
		if p.isConnectionAlive(pooledConn.client) {
			pooledConn.mu.Lock()
			pooledConn.lastUsed = time.Now()
			// Note: SSH connections can handle multiple concurrent sessions
			// so we don't need to mark as "inUse" in an exclusive way
			pooledConn.retryCount = 0 // Reset retry count
			pooledConn.mu.Unlock()
			p.mu.Unlock()
			lg.Debug("🔄 Reusing existing connection from pool for %s", key)
			return pooledConn.client, nil
		}

		// Connection is invalid, remove and recreate
		lg.Debug("❌ Connection invalid, removing from pool for %s", key)
		pooledConn.mu.Lock()
		if pooledConn.client != nil {
			_ = errutil.SafeClose(pooledConn.client) //nolint:errcheck
		}
		pooledConn.mu.Unlock()
		delete(p.connections, key)
	}
	p.mu.Unlock()

	lg.Debug("➕ Creating new connection for pool key %s", key)
	// Create new connection with retry mechanism
	client, err := p.createConnectionWithRetry(config)
	if err != nil {
		return nil, err
	}

	// Add to connection pool
	pooledConn = &PooledConnection{
		client:     client,
		config:     config,
		lastUsed:   time.Now(),
		inUse:      false, // SSH connections can handle multiple sessions
		retryCount: 0,
	}

	p.mu.Lock()
	p.connections[key] = pooledConn
	lg.Debug("✅ Added new connection to pool, total connections: %d", len(p.connections))
	p.mu.Unlock()

	return client, nil
}

// ReleaseConnection updates the last used time for a connection
func (p *ConnectionPool) ReleaseConnection(config *Config) {
	key := p.makeKey(config)

	p.mu.RLock()
	pooledConn, exists := p.connections[key]
	p.mu.RUnlock()

	if exists {
		pooledConn.mu.Lock()
		// Just update the last used time since SSH connections can handle multiple sessions
		pooledConn.lastUsed = time.Now()
		pooledConn.mu.Unlock()
	}
}

// RemoveConnection removes a connection from the pool (used when connection fails)
func (p *ConnectionPool) RemoveConnection(config *Config) {
	key := p.makeKey(config)
	lg := logger.GetLogger()

	p.mu.Lock()
	defer p.mu.Unlock()

	if pooledConn, exists := p.connections[key]; exists {
		pooledConn.mu.Lock()
		if pooledConn.client != nil {
			_ = errutil.SafeClose(pooledConn.client) //nolint:errcheck
		}
		pooledConn.mu.Unlock()
		delete(p.connections, key)
		lg.Debug("🗑️  Removed failed connection from pool: %s", key)
	}
}

// createConnectionWithRetry creates a connection with retry mechanism
func (p *ConnectionPool) createConnectionWithRetry(config *Config) (*ssh.Client, error) {
	var lastErr error

	for i := 0; i < p.maxRetries; i++ {
		if i > 0 {
			time.Sleep(p.retryDelay * time.Duration(i)) // Exponential backoff
		}

		client, err := p.createConnection(config)
		if err == nil {
			return client, nil
		}

		lastErr = err
	}

	return nil, fmt.Errorf("failed after %d retries: %w", p.maxRetries, lastErr)
}

// createConnection creates a single SSH connection (direct connection, not using pool)
func (p *ConnectionPool) createConnection(config *Config) (*ssh.Client, error) {
	sshClient, err := NewSSHClient(config)
	if err != nil {
		return nil, err
	}

	// Use ConnectDirect() to avoid recursive pool calls
	if err := sshClient.ConnectDirect(); err != nil {
		return nil, err
	}

	return sshClient.client, nil
}

// isConnectionAlive checks if a connection is alive
func (p *ConnectionPool) isConnectionAlive(client *ssh.Client) bool {
	if client == nil {
		return false
	}

	// First, try to create a session - this is a lightweight check
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer func() {
		_ = errutil.SafeClose(session) //nolint:errcheck
	}()

	// Set a timeout for the health check to avoid hanging
	done := make(chan error, 1)
	go func() {
		// Execute a lightweight command to truly verify the connection is alive
		// This catches EOF and other connection issues that NewSession alone might miss
		done <- session.Run("echo ping")
	}()

	select {
	case err := <-done:
		return err == nil
	case <-time.After(5 * time.Second):
		// Health check timeout - connection is likely dead
		return false
	}
}

// makeKey generates a connection pool key
func (p *ConnectionPool) makeKey(config *Config) string {
	return fmt.Sprintf("%s@%s:%s", config.User, config.Host, config.Port)
}

// startMaintenance starts background maintenance tasks
func (p *ConnectionPool) startMaintenance() {
	ticker := time.NewTicker(p.healthCheck)
	defer ticker.Stop()

	for range ticker.C {
		p.cleanup()
	}
}

// cleanup removes expired and invalid connections
func (p *ConnectionPool) cleanup() {
	now := time.Now()
	var toRemove []string

	p.mu.RLock()
	for key, pooledConn := range p.connections {
		pooledConn.mu.Lock()

		// Check if exceeded max idle time
		if now.Sub(pooledConn.lastUsed) > p.maxIdle {
			toRemove = append(toRemove, key)
		} else if !p.isConnectionAlive(pooledConn.client) {
			// Connection is invalid
			toRemove = append(toRemove, key)
		}

		pooledConn.mu.Unlock()
	}
	p.mu.RUnlock()

	// Remove invalid connections
	if len(toRemove) > 0 {
		lg := logger.GetLogger()
		p.mu.Lock()
		for _, key := range toRemove {
			if pooledConn, exists := p.connections[key]; exists {
				if pooledConn.client != nil {
					if err := errutil.SafeClose(pooledConn.client); err != nil {
						lg.Debug("Failed to close pooled connection %s: %v", key, err)
					}
				}
				delete(p.connections, key)
			}
		}
		p.mu.Unlock()
		lg.Debug("Cleaned up %d expired/invalid connections", len(toRemove))
	}
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() {
	lg := logger.GetLogger()
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error
	for key, pooledConn := range p.connections {
		if pooledConn.client != nil {
			if err := errutil.SafeClose(pooledConn.client); err != nil {
				lg.Debug("Failed to close connection %s: %v", key, err)
				errs = append(errs, err)
			}
		}
	}

	p.connections = make(map[string]*PooledConnection)

	if len(errs) > 0 {
		lg.Warning("Closed connection pool with %d errors", len(errs))
	} else {
		lg.Debug("Successfully closed all connections in pool")
	}
}

// Stats returns connection pool statistics
func (p *ConnectionPool) Stats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	totalConns := len(p.connections)
	recentlyUsed := 0

	now := time.Now()
	recentThreshold := 1 * time.Minute // Consider connections used in last minute as "active"

	for _, pooledConn := range p.connections {
		pooledConn.mu.Lock()
		if now.Sub(pooledConn.lastUsed) < recentThreshold {
			recentlyUsed++
		}
		pooledConn.mu.Unlock()
	}

	return map[string]interface{}{
		"total_connections":         totalConns,
		"recently_used_connections": recentlyUsed,
		"idle_connections":          totalConns - recentlyUsed,
		"max_idle_duration":         p.maxIdle.String(),
		"health_check_interval":     p.healthCheck.String(),
	}
}
