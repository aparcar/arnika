//go:build wireguard_netlink || (!wireguard_mikrotik && !wireguard_netlink_netns)

package main

import (
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories"
	"github.com/arnika-project/arnika/services"
)

func getKeyWriterService(cfg *config.Config) (*services.KeyWriterService, error) {
	if err := cfg.RequireWireGuardPeer(); err != nil {
		return nil, err
	}
	wireguardRepo, err := repositories.NewWireguardNetlinkRepository(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey)
	if err != nil {
		return nil, err

	}
	return services.NewKeyWriterService(wireguardRepo), nil
}
