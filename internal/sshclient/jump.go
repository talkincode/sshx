package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// HopIdentity is the public, secret-free record of one SSH hop.
type HopIdentity struct {
	Role               string
	Alias              string
	Address            string
	Port               string
	User               string
	PeerAddress        string
	HostKeyFingerprint string
	AuthMethod         string
	Closed             bool
	CloseError         string
}

// HopError marks which hop failed without inventing a new error_kind.
type HopError struct {
	Role  string
	Alias string
	Err   error
}

func (e *HopError) Error() string {
	if e == nil || e.Err == nil {
		return "hop error"
	}
	if e.Alias == "" {
		return fmt.Sprintf("%s hop: %v", e.Role, e.Err)
	}
	return fmt.Sprintf("%s hop %s: %v", e.Role, e.Alias, e.Err)
}

func (e *HopError) Unwrap() error { return e.Err }

func (e *HopError) ErrorKind() string {
	if e == nil {
		return "connect"
	}
	var typed interface{ ErrorKind() string }
	if errors.As(e.Err, &typed) && typed.ErrorKind() != "" {
		return typed.ErrorKind()
	}
	return "connect"
}

func hopError(role string, cfg *Config, err error) error {
	if err == nil {
		return nil
	}
	alias := ""
	if cfg != nil {
		alias = cfg.HostAlias
		if alias == "" {
			alias = cfg.Host
		}
	}
	return &HopError{Role: role, Alias: alias, Err: err}
}

func dialJump(ctx context.Context, parent *ssh.Client, addr string) (net.Conn, error) {
	if parent == nil {
		return nil, fmt.Errorf("missing jump client")
	}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	done := make(chan dialResult, 1)
	go func() {
		conn, err := parent.Dial("tcp", addr)
		done <- dialResult{conn, err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			result := <-done
			if result.conn != nil {
				_ = result.conn.Close() //nolint:errcheck // canceled jump dial
			}
		}()
		return nil, ctx.Err()
	case result := <-done:
		return result.conn, result.err
	}
}

// JumpCache holds process-scoped bastion sessions for one CLI invocation.
type JumpCache struct {
	mu   sync.Mutex
	hops map[string]*SSHClient
}

// NewJumpCache returns an empty cache. Close releases every hop.
func NewJumpCache() *JumpCache {
	return &JumpCache{hops: map[string]*SSHClient{}}
}

func hopCacheKey(parentKey string, cfg *Config) string {
	if cfg == nil {
		return parentKey
	}
	return parentKey + "\x00" + cfg.Host + "\x00" + cfg.Port + "\x00" + cfg.User + "\x00" + cfg.KeyPath + "\x00" + cfg.SSHPasswordKey
}

func (c *JumpCache) acquire(ctx context.Context, cfg *Config) (*ssh.Client, []*SSHClient, error) {
	if c == nil || cfg == nil || len(cfg.JumpChain) == 0 {
		return nil, nil, nil
	}
	var (
		parent    *ssh.Client
		parentKey string
		chain     []*SSHClient
	)
	for _, hop := range cfg.JumpChain {
		if hop == nil {
			return nil, nil, hopError("jump", hop, fmt.Errorf("jump config is required"))
		}
		key := hopCacheKey(parentKey, hop)
		client, err := c.getOrConnect(ctx, key, hop, parent)
		if err != nil {
			return nil, nil, hopError("jump", hop, err)
		}
		chain = append(chain, client)
		next, sshErr := client.sshConnection()
		if sshErr != nil {
			return nil, nil, hopError("jump", hop, sshErr)
		}
		parent = next
		parentKey = key
	}
	return parent, chain, nil
}

func (c *JumpCache) getOrConnect(ctx context.Context, key string, hop *Config, parent *ssh.Client) (*SSHClient, error) {
	c.mu.Lock()
	if existing, ok := c.hops[key]; ok {
		c.mu.Unlock()
		return existing, nil
	}
	c.mu.Unlock()

	hopCopy := *hop
	hopCopy.JumpChain = nil
	if ctx != nil {
		hopCopy.Context = ctx
	}
	client, err := NewSSHClient(&hopCopy)
	if err != nil {
		return nil, err
	}
	if err := client.connectThrough(parent); err != nil {
		_ = client.Close() //nolint:errcheck // failed hop must not stay cached
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.hops[key]; ok {
		_ = client.Close() //nolint:errcheck // lost the publish race
		return existing, nil
	}
	c.hops[key] = client
	return client, nil
}

// Close tears down every cached bastion session.
func (c *JumpCache) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var first error
	for key, hop := range c.hops {
		if err := hop.Close(); err != nil && first == nil {
			first = err
		}
		delete(c.hops, key)
	}
	return first
}

// CacheDialer reuses bastion sessions for one Execute() fan-out.
type CacheDialer struct {
	Cache   *JumpCache
	Context context.Context
}

// Connect implements execution.Dialer.
func (d CacheDialer) Connect(cfg *Config) (*SSHClient, error) {
	if cfg == nil {
		return nil, boundaryError("config", "connect", fmt.Errorf("config is required"))
	}
	cache := d.Cache
	if cache == nil {
		cache = NewJumpCache()
	}
	parent, hops, err := cache.acquire(d.Context, cfg)
	if err != nil {
		return nil, err
	}
	client, err := NewSSHClient(cfg)
	if err != nil {
		return nil, err
	}
	client.sharedJumps = hops
	if err := client.connectThrough(parent); err != nil {
		_ = client.Close() //nolint:errcheck // failed target must not leak the channel
		return nil, err
	}
	return client, nil
}
