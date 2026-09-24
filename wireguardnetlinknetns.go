//go:build wireguard_netlink_netns

package main

import (
	"os"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories"
	"github.com/arnika-project/arnika/services"
)

func getKeyWriterService(cfg *config.Config) (*services.KeyWriterService, error) {
	if err := cfg.RequireWireGuardPeer(); err != nil {
		return nil, err
	}
	netnsPath := os.Getenv("WIREGUARD_NETNS_PATH")
	wireguardRepo, err := repositories.NewWireguardNetlinkNetnsRepository(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey, netnsPath)
	if err != nil {
		return nil, err
	}
	return services.NewKeyWriterService(wireguardRepo), nil
}
