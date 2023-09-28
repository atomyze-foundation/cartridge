# cartridge

Library for working with crypto providers, for example, Vault or GCP. This library will most likely be replaced with "inject" in services. #go#library#crypto#secops#offchain#service#application#

## Table of Contents

- [cartridge](#-cartridge)
	- [Table of Contents](#-table-of-contents)
	- [Description](#-description)
	- [Links](#-links)
	- [License](#-license)

## Description

How to use Cartridge with Vault:

```go
package main

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/sirupsen/logrus"
	"github.com/atomyze-foundation/cartridge"
	"github.com/atomyze-foundation/cartridge/manager"
)

func main() {
	// create manager instance
	userCert := "User1@org1.example.com-cert.pem"
	vaultManager, err := manager.NewVaultManager("Org1MSP", userCert, "http://dev-vault:8200", "secrettoken", "kv")
	if err != nil {
		logrus.Fatal(err)
	}

	configProvider := config.FromFile("connectionProfilePath")
	configBackends, err := configProvider()
	if err != nil {
		logrus.Fatal(err)
	}

	connectOpts, err := cartridge.NewConnector(vaultManager, cartridge.NewVaultConnectProvider(configBackends...)).Opts()
	if err != nil {
		logrus.Fatal(err)
	}

	sdk, err := fabsdk.New(configProvider, connectOpts...)
	if err is not nil {
		logrus.Fatal(err)
	}

	// create a channel.Client with signing identity
	signingIdentity := vaultManager.SigningIdentity()
	channelProvider := sdk.ChannelContext("mychannel", fabsdk.WithOrg("Org1"), fabsdk.WithIdentity(signingIdentity))
	cli, err := channel.New(channelProvider)
	if err != nil {
		logrus.Fatal(err)
	}
}
```

How to use Cartridge with Google Secrets:

Define an environment variable with the path to service account credentials:
```shell
export GOOGLE_APPLICATION_CREDENTIALS=$(pwd)/sa-app.json
```

```go
package main

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/sirupsen/logrus"
	"github.com/atomyze-foundation/cartridge"
	"github.com/atomyze-foundation/cartridge/manager"
)

func main() {
	userCert := "User1@org1.example.com-cert.pem"

	secretManager, err := manager.NewSecretManager("Org1MSP", "gcp-project", userCert)
	if err != nil {
		logrus.Fatal(err)
	}

	configProvider := config.FromFile("connectionProfilePath")
	configBackends, err := configProvider()
	if err != nil {
		logrus.Fatal(err)
	}

	connectOpts, err := cartridge.NewConnector(secretManager, cartridge.NewVaultConnectProvider(configBackends...)).Opts()
	if err != nil {
		logrus.Fatal(err)
	}

	sdk, err := fabsdk.New(configProvider, connectOpts...)
	if err != nil {
		logrus.Fatal(err)
	}

	signingIdentity := secretManager.SigningIdentity()
	channelProvider := sdk.ChannelContext("channel0", fabsdk.WithOrg("Org1"), fabsdk.WithIdentity(signingIdentity))
	_, err = channel.New(channelProvider)
	if err != nil {
		logrus.Fatal(err)
	}
}

```

To integrate your own crypto storage for your signing crypto, you need to implement the [Manager](https://github.com/atomyze-foundation/cartridge/-/blob/main/manager/manager.go) interface and provide this implementation to the [NewConnector](https://github.com/atomyze-foundation/cartridge/-/blob/main/connector.go#L22) constructor as shown above. If you want to implement storage for all user's crypto, you need to implement the [ConnectProvider](https://github.com/atomyze-foundation/cartridge/-/blob/main/connectprovider.go) interface and pass it to [NewConnector](https://github.com/atomyze-foundation/cartridge/-/blob/main/connector.go#L22) as well.

## Links

* [original repository](https://github.com/atomyze-foundation/cartridge)

## License

[Default License](LICENSE)
