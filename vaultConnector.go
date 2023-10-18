/*
Copyright Idea LCC. All Rights Reserved.

SPDX-License-Identifier: [Default license](LICENSE)
*/

package cartridge

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/atomyze-foundation/cartridge/connector/vaultconnector"
	"github.com/atomyze-foundation/cartridge/cryptocache"
)

type VaultConnector struct {
	coreBackend           []core.ConfigBackend
	ChannelConfigProvider func(name string) *fab.ChannelEndpointConfig
	ChannelPeersProvider  func(channel string) []fab.ChannelPeer
}

func NewVaultConnectProvider(coreBackend ...core.ConfigBackend) *VaultConnector {
	return &VaultConnector{
		coreBackend: coreBackend,
	}
}

func (c *VaultConnector) WithChannelConfigProvider(channelConfigProvider func(name string) *fab.ChannelEndpointConfig) {
	c.ChannelConfigProvider = channelConfigProvider
}

func (c *VaultConnector) WithChannelPeersProvider(channelPeersProvider func(channel string) []fab.ChannelPeer) {
	c.ChannelPeersProvider = channelPeersProvider
}

func (c *VaultConnector) IdentityConfig(cache cryptocache.CryptoCache) (msp.IdentityConfig, error) {
	return vaultconnector.IdentityConfigFromBackend(cache, c.coreBackend...)
}

func (c *VaultConnector) EndpointConfig(cache cryptocache.CryptoCache) (fab.EndpointConfig, error) {
	return vaultconnector.EndpointConfigFromBackend(cache, c.ChannelConfigProvider, c.ChannelPeersProvider, c.coreBackend...)
}
