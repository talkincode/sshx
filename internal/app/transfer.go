package app

import (
	"fmt"

	"github.com/talkincode/sshx/internal/sshclient"
	"github.com/talkincode/sshx/pkg/logger"
)

// HandleTransfer performs a direct server-to-server file transfer. It opens
// SSH connections to both the source and destination hosts and streams data
// between them through the local machine without touching local disk.
func HandleTransfer(config *sshclient.Config) (err error) {
	lg := logger.GetLogger()

	if config.TransferSrcHost == "" || config.TransferSrcPath == "" {
		return fmt.Errorf("source must be specified as --transfer=<host>:<path>")
	}
	if config.TransferDstHost == "" || config.TransferDstPath == "" {
		return fmt.Errorf("destination must be specified as --to=<host>:<path>")
	}

	srcClient, err := connectTransferEndpoint(config, config.TransferSrcHost, "source")
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := srcClient.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	dstClient, err := connectTransferEndpoint(config, config.TransferDstHost, "destination")
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := dstClient.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	lg.Info("Transfer: %s:%s → %s:%s",
		config.TransferSrcHost, config.TransferSrcPath,
		config.TransferDstHost, config.TransferDstPath)

	if err = srcClient.TransferTo(dstClient, config.TransferSrcPath, config.TransferDstPath); err != nil {
		return err
	}

	lg.Success("Transfer completed: %s:%s → %s:%s",
		config.TransferSrcHost, config.TransferSrcPath,
		config.TransferDstHost, config.TransferDstPath)
	return nil
}

// connectTransferEndpoint builds a per-endpoint config derived from the base
// invocation, resolves the host from settings when applicable, and returns a
// connected SSH client.
func connectTransferEndpoint(base *sshclient.Config, host, role string) (*sshclient.SSHClient, error) {
	endpoint := &sshclient.Config{
		Host:                 host,
		Port:                 base.Port,
		User:                 base.User,
		Password:             base.Password,
		KeyPath:              base.KeyPath,
		UseKeyAuth:           base.UseKeyAuth,
		SudoKey:              base.SudoKey,
		DialTimeout:          base.DialTimeout,
		AcceptUnknownHost:    base.AcceptUnknownHost,
		AllowInsecureHostKey: base.AllowInsecureHostKey,
		KnownHostsPath:       base.KnownHostsPath,
	}

	if !isIPAddress(endpoint.Host) {
		if resolveErr := resolveHostFromSettings(endpoint); resolveErr != nil {
			logger.GetLogger().Info("Note: Could not find %s host '%s' in settings, using as hostname directly", role, endpoint.Host)
		}
	}

	client, err := sshclient.NewSSHClient(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH client for %s host %s: %w", role, host, err)
	}
	if err := client.ConnectDirect(); err != nil {
		return nil, fmt.Errorf("failed to connect to %s host %s: %w", role, host, err)
	}
	return client, nil
}
