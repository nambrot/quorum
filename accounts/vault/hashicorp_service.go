package vault

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

type hashicorpService struct {
	clientFactory func() (clientI, error)
	clientConfig ClientConfig
	secrets []Secret
	client clientI
	secretsByAccount map[accounts.Account]Secret
}

func NewHashicorpService(clientConfig ClientConfig, secrets []Secret) VaultService {
	return &hashicorpService{
		clientFactory: createDefaultClient,
		clientConfig: clientConfig,
		secrets: secrets,
	}
}

func createDefaultClient() (clientI, error) {
	conf := api.DefaultConfig()
	client, err := api.NewClient(conf)

	if err != nil {
		return nil, err
	}

	return clientDelegate{client}, nil
}

const (
	walletClosed = "Closed"
	vaultUninitialised = "Vault uninitialised"
	vaultSealed = "Vault sealed"
	healthcheckFailed = "Vault healthcheck failed"
	walletOpen = "Open, vault initialised and unsealed"
)

func (s *hashicorpService) Status() (string, error) {
	if s.client == nil {
		return walletClosed, nil
	}

	health, err := s.client.Sys().Health()

	if err != nil {
		return healthcheckFailed, err
	}

	if !health.Initialized {
		return vaultUninitialised, errors.New(vaultUninitialised)
	}

	if health.Sealed {
		return vaultSealed, errors.New(vaultSealed)
	}

	return walletOpen, nil
}

func (s *hashicorpService) Open() error {
	panic("implement me")
}

func (*hashicorpService) Close() error {
	panic("implement me")
}

func (*hashicorpService) GetPrivateKey(account accounts.Account) (*ecdsa.PrivateKey, error) {
	panic("implement me")
}

func (*hashicorpService) Store(key *ecdsa.PrivateKey) (common.Address, error) {
	panic("implement me")
}

