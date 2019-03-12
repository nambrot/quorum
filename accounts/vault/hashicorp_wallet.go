package vault

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/vault/api"
	"math/big"
	"os"
	"strconv"
	"sync"
)

const (
	vaultRoleId = "VAULT_ROLE_ID"
	vaultSecretId = "VAULT_SECRET_ID"
	vaultApprolePath = "VAULT_APPROLE_PATH"
)

var (
	secretEngineName = "kv"
	secrets = []secretData {
		{"mySecret", "kv", 0, "publicKey", "privateKey"},
		{"tessera", "kv", 0, "publicKey", "privateKey"},
		{"two", "kv", 0, "publicKey", "privateKey"},
	}
)

type hashicorpWallet struct {
	stateLock sync.RWMutex  // Protects read and write access to the wallet struct fields
	clientData clientData
	secrets []secretData
	accounts []accounts.Account
	accountsSecretMap map[accounts.Account]secretData
	client clientInterface
}

type clientData struct {
	url string
	approle string
	caCert string
	clientCert string
	clientKey string
}

type secretData struct {
	name string
	secretEngine string
	version int
	publicKeyId string
	privateKeyId string
}

type secret struct {
	key string
	value string
}

func newHashicorpWallet(clientData clientData, secrets []secretData) *hashicorpWallet {
	hw := &hashicorpWallet{
		clientData: clientData,
		secrets: secrets,
	}

	hw.refresh()

	return hw
}

//=======================

type clientInterface interface {
	doLogical() logicalInterface
	doSetToken(token string)
	doClearToken()
}

type clientImpl struct {
	*api.Client
}

func (c clientImpl) doLogical() logicalInterface {
	return logicalImpl{c.Logical()}
}

func (c clientImpl) doSetToken(token string) {
	c.SetToken(token)
}

func (c clientImpl) doClearToken() {
	c.ClearToken()
}

//=======================

type logicalInterface interface {
	doReadWithData(path string, data map[string][]string) (*api.Secret, error)
	doWrite(path string, data map[string]interface{}) (*api.Secret, error)
}

type logicalImpl struct {
	*api.Logical
}

func (l logicalImpl) doReadWithData(path string, data map[string][]string) (*api.Secret, error) {
	return l.ReadWithData(path, data)
}

func (l logicalImpl) doWrite(path string, data map[string]interface{}) (*api.Secret, error) {
	return l.Write(path, data)
}

//=======================

func (hw *hashicorpWallet) read(secretEngineName string, secretName string, secretVersion int) (*api.Secret, error)  {
	path := fmt.Sprintf("%s/data/%s", secretEngineName, secretName)

	queryParams := make(map[string][]string)
	if secretVersion < 0 {
		//TODO custom error type?
		return nil, errors.New("Hashicorp Vault secret version must be integer >= 0")
	}
	queryParams["version"] = []string{strconv.Itoa(secretVersion)}

	return hw.client.doLogical().doReadWithData(path, queryParams)
}

func (*hashicorpWallet) URL() accounts.URL {
	panic("implement me")
}

func (*hashicorpWallet) Status() (string, error) {
	panic("implement me")
}

// Open implements accounts.Wallet, creating an authenticated Client and making it accessible to the wallet to enable vault operations.
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

	if cli, err := api.NewClient(c); err != nil {
		return err
	} else {
		hw.client = clientImpl{cli}
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

		hw.clientData.approle = approlePath

		authResponse, err := hw.client.doLogical().doWrite(fmt.Sprintf("auth/%s/login", hw.clientData.approle), authData)

		if err != nil {
			return err
		}

		token := authResponse.Auth.ClientToken
		hw.client.doSetToken(token)
	}

	// TODO If not set manually, token is set by reading VAULT_TOKEN.  The non-approle case will only have to be explicitly handled if using CLI/file config

	return nil
}

// Close implements accounts.Wallet, clearing the state of the wallet and removing the vault Client so vault operations can no longer be carried out.
func (hw *hashicorpWallet) Close() error {
	hw.stateLock.Lock()
	defer hw.stateLock.Unlock()

	if hw.client == nil {
		return nil
	}

	hw.client.doClearToken()
	hw.client = nil
	// What else to do here?

	return nil
}

// Account implements accounts.Wallet, returning the accounts specified in config that are stored in the vault.
func (hw *hashicorpWallet) Accounts() []accounts.Account {
	return hw.accounts
}

//// Account implements accounts.Wallet, returning the accounts specified in config that are stored in the vault
//func (hw *hashicorpWallet) Accounts() []accounts.Account {
//	hw.stateLock.Lock()
//	defer hw.stateLock.Unlock()
//
//	accts := make([]accounts.Account, len(secrets))
//
//	var acct accounts.Account
//
//	for i, secret := range hw.secrets {
//		account, err := hw.getAccount(secretEngineName, secret.name, secret.version)
//		if err != nil {
//			panic("implement me")
//		}
//
//		accts[i] = account
//	}
//
//	return accts
//}

// Contains implements accounts.Wallet, returning whether a particular account is managed by this wallet.
func (hw *hashicorpWallet) Contains(account accounts.Account) bool {
	hw.stateLock.RLock()
	defer hw.stateLock.RUnlock()

	for _, acct := range hw.accounts {
		if acct.Address == account.Address {
			return true
		}
	}

	return false
}

// Derive implements accounts.Wallet, but is a noop for Vault wallets since these have no notion of hierarchical account derivation.
func (*hashicorpWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, accounts.ErrNotSupported
}

// SelfDerive implements accounts.Wallet, but is a noop for Vault wallets since these have no notion of hierarchical account derivation.
func (*hashicorpWallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {
	log.Warn("SelfDerive is not supported for Hashicorp Vault wallets")
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

func (hw *hashicorpWallet) getAccount(secretData secretData) (accounts.Account, error) {
	secret, err := hw.read(secretData.secretEngine, secretData.name, secretData.version)

	if err != nil {
		return accounts.Account{}, err
	}

	data := secret.Data["data"]

	m := data.(map[string]interface{})
	pubKey, ok := m[secretData.publicKeyId]

	if !ok {
		//TODO change this error
		return accounts.Account{}, accounts.ErrUnknownAccount
	}

	pk, errr := pubKey.(string)

	if errr {
		//TODO throw error as value retrieved from vault is not of type string
	}

	account := accounts.Account{Address: common.StringToAddress(pk)}

	return account, nil
}

func (hw *hashicorpWallet) refresh() error {
	//TODO don't just overwrite, check existing accounts
	accts := make([]accounts.Account, len(secrets))
	acctsScrtsMap := make(map[accounts.Account]secretData)

	for i, secret := range hw.secrets {
		acct, err := hw.getAccount(secret)

		if err != nil {
			return err
		}

		accts[i] = acct
		acctsScrtsMap[acct] = secret
	}

	hw.accounts = accts
	hw.accountsSecretMap = acctsScrtsMap

	return nil
}

