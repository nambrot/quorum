package vault

import (
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/hashicorp/vault/api"
	"math/big"
	"os"
	"sync"
)

const (
	vaultRoleId = "VAULT_ROLE_ID"
	vaultSecretId = "VAULT_SECRET_ID"
	vaultApprolePath = "VAULT_APPROLE_PATH"
)

type hashicorpWallet struct {
	client *api.Client
	approlePath string
	stateLock sync.RWMutex  // Protects read and write access to the wallet struct fields
}

func (*hashicorpWallet) URL() accounts.URL {
	panic("implement me")
}

func (*hashicorpWallet) Status() (string, error) {
	panic("implement me")
}

// Open implements accounts.Wallet, establishing a connection to the Hashicorp vault and making the resulting Client accessible to the wallet.
//
// If Approle credentials have been provided these will be used to authenticate the Client with the vault, else the Token will be used.
//
// The passphrase arg is not used and this method does not retrieve any secrets from the vault.
func (hw *hashicorpWallet) Open(passphrase string) error {
	hw.stateLock.Lock() // State lock is enough since there's no connection yet at this point
	defer hw.stateLock.Unlock()

	// TODO is this check sufficient?
	// If the vault client has already been created, don't create again
	if hw.client != nil {
		return accounts.ErrWalletAlreadyOpen
	}

	c := api.DefaultConfig()

	var err error
	if hw.client, err = api.NewClient(c); err != nil {
		return err
	}

	// Authenticate the vault client, if Approle credentials not provided use Token
	roleId, rIdOk := os.LookupEnv(vaultRoleId)
	secretId, sIdOk := os.LookupEnv(vaultSecretId)

	if rIdOk && sIdOk {
		authData := map[string]interface{} {"role_id": roleId, "secret_id": secretId}

		approlePath, apOk := os.LookupEnv(vaultApprolePath)

		if !apOk {
			approlePath = "approle"
		}

		authResponse, err := hw.client.Logical().Write(fmt.Sprintf("auth/%s/login", approlePath), authData)

		if err != nil {
			return err
		}

		token := authResponse.Auth.ClientToken
		hw.client.SetToken(token)
	}

	// TODO If not set manually, token is set by reading VAULT_TOKEN.  The non-approle case will only have to be explicitly handled if using CLI/file config

	return nil
}

func (*hashicorpWallet) Close() error {
	panic("implement me")
}

func (*hashicorpWallet) Accounts() []accounts.Account {
	panic("implement me")
}

func (*hashicorpWallet) Contains(account accounts.Account) bool {
	panic("implement me")
}

func (*hashicorpWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	panic("implement me")
}

func (*hashicorpWallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {
	panic("implement me")
}

func (*hashicorpWallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	panic("implement me")
}

func (*hashicorpWallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int, isQuorum bool) (*types.Transaction, error) {
	panic("implement me")
}

func (*hashicorpWallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	panic("implement me")
}

func (*hashicorpWallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	panic("implement me")
}


