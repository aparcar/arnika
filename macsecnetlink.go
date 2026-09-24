//go:build macsec_netlink && linux

package main

import (
	"fmt"
	"os"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/repositories"
	"github.com/arnika-project/arnika/services"
)

// getKeyWriterService wires the MACsec generic netlink key writer. MACsec has
// no WireGuard peer, so it reads its own interface and the peer's RX SCI here
// instead of using the WireGuard settings from the shared config.
func getKeyWriterService(_ *config.Config) (*services.KeyWriterService, error) {
	iface := os.Getenv("MACSEC_INTERFACE")
	if iface == "" {
		return nil, fmt.Errorf("[ERROR] MACSEC_INTERFACE is required for the macsec_netlink build")
	}
	rxSCI := os.Getenv("MACSEC_RX_SCI")
	if rxSCI == "" {
		return nil, fmt.Errorf("[ERROR] MACSEC_RX_SCI is required for the macsec_netlink build")
	}
	repo, err := repositories.NewMacsecNetlinkRepository(iface, rxSCI)
	if err != nil {
		return nil, err
	}
	return services.NewKeyWriterService(repo), nil
}
