package vault

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/vault/api"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	vaultRoleId = "VAULT_ROLE_ID"
	vaultSecretId = "VAULT_SECRET_ID"
	vaultApprolePath = "VAULT_APPROLE_PATH"
)

type hashicorpWallet struct {
	stateLock sync.RWMutex  // Protects read and write access to the wallet struct fields
	url accounts.URL
	clientData ClientData
	secrets []SecretData
	accounts []accounts.Account
	accountsSecretMap map[common.Address]SecretData
	client clientI
	updateFeed *event.Feed
}

type ClientData struct {
	Url        string `toml:",omitempty"`
	Approle    string `toml:",omitempty"`
	CaCert     string `toml:",omitempty"`
	ClientCert string `toml:",omitempty"`
	ClientKey  string `toml:",omitempty"`
}

type SecretData struct {
	Name         string `toml:",omitempty"`
	SecretEngine string `toml:",omitempty"`
	Version      int    `toml:",omitempty"`
	PublicKeyId  string `toml:",omitempty"`
	PrivateKeyId string `toml:",omitempty"`
}

func (s SecretData) toRequestData() (string, map[string][]string, error) {

	path := fmt.Sprintf("%s/data/%s", s.SecretEngine, s.Name)

	queryParams := make(map[string][]string)
	if s.Version < 0 {
		//TODO custom error type?
		return "", nil, fmt.Errorf("Hashicorp Vault secret version must be integer >= 0")
	}
	queryParams["version"] = []string{strconv.Itoa(s.Version)}

	return path, queryParams, nil
}

func NewHashicorpWallet(clientData ClientData, secrets []SecretData, updateFeed *event.Feed) (*hashicorpWallet, error) {
	hw, err := newHashicorpWallet(clientData, secrets)
	hw.updateFeed = updateFeed

	return hw, err
}

// TODO revisit comment
// separate method so that it can be used to create full wallet and for geth account new
func newHashicorpWallet(clientData ClientData, secrets []SecretData) (*hashicorpWallet, error) {
	url, err := parseURL(clientData.Url)

	if err != nil {
		return &hashicorpWallet{}, err
	}

	hw := &hashicorpWallet{
		clientData: clientData,
		secrets: secrets,
		url: url,
	}

	return hw, nil
}

type clientI interface {
	Logical() logicalI
	Sys() sysI
	SetAddress(addr string) error
	SetToken(v string)
	ClearToken()
}

type logicalI interface{
	ReadWithData(path string, data map[string][]string) (*api.Secret, error)
	Write(path string, data map[string]interface{}) (*api.Secret, error)
}

type sysI interface{
	Health() (*api.HealthResponse, error)
}

type clientDelegate struct {
	*api.Client
}

func (cd clientDelegate) Logical() logicalI {
	return cd.Client.Logical()
}

func (cd clientDelegate) Sys() sysI {
	return cd.Client.Sys()
}

func (hw *hashicorpWallet) URL() accounts.URL {
	return hw.url
}

const (
	walletClosed = "Closed"
	vaultUninitialised = "Vault uninitialised"
	vaultSealed = "Vault sealed"
	healthcheckFailed = "Vault healthcheck failed"
	walletOpen = "Open, vault initialised and unsealed"
)

func (hw *hashicorpWallet) Status() (string, error) {
	hw.stateLock.Lock()
	defer hw.stateLock.Unlock()

	if hw.client == nil {
		return walletClosed, nil
	}

	health, err := hw.client.Sys().Health()

	if err != nil {
		return healthcheckFailed, err
	}

	if !health.Initialized {
		return vaultUninitialised, fmt.Errorf("Vault health check, Initialized: %v, Sealed: %v", health.Initialized, health.Sealed)
	}

	if health.Sealed {
		return vaultSealed, fmt.Errorf("Vault health check, Initialized: %v, Sealed: %v", health.Initialized, health.Sealed)
	}

	return walletOpen, nil
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
		hw.client = clientDelegate{cli}
	}

	err := hw.client.SetAddress(hw.clientData.Url)

	if err != nil {
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

		hw.clientData.Approle = approlePath

		authResponse, err := hw.client.Logical().Write(fmt.Sprintf("auth/%s/login", hw.clientData.Approle), authData)

		if err != nil {
			return err
		}

		token := authResponse.Auth.ClientToken
		hw.client.SetToken(token)
	}

	// TODO If not set manually, token is set by reading VAULT_TOKEN.  The non-approle case will only have to be explicitly handled if using CLI/file config

	hw.updateFeed.Send(
		accounts.WalletEvent{hw, accounts.WalletOpened},
	)

	return nil
}

// Close implements accounts.Wallet, clearing the state of the wallet and removing the vault Client so vault operations can no longer be carried out.
func (hw *hashicorpWallet) Close() error {
	hw.stateLock.Lock()
	defer hw.stateLock.Unlock()

	if hw.client == nil {
		return nil
	}

	hw.client.ClearToken()
	hw.client = nil //TODO set back to defaults
	// What else to do here?

	return nil
}

// Account implements accounts.Wallet, returning the accounts specified in config that are stored in the vault.
func (hw *hashicorpWallet) Accounts() []accounts.Account {
	if err := hw.refresh(); err != nil {
		//TODO handle
	}

	cpy := make([]accounts.Account, len(hw.accounts))
	copy(cpy, hw.accounts)

	return cpy
}

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

func (hw *hashicorpWallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	hw.stateLock.RLock()
	defer hw.stateLock.RUnlock()

	if hw.client == nil {
		return nil, accounts.ErrWalletClosed
	}

	secretData, ok := hw.accountsSecretMap[account.Address]
	if !ok {
		return nil, accounts.ErrUnknownAccount
	}

	key, err := hw.getPrivateKey(secretData)
	if(err != nil) {
		return nil, err
	}
	defer zeroKey(key)

	return crypto.Sign(hash, key)
}

func (hw *hashicorpWallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int, isQuorum bool) (*types.Transaction, error) {

	hw.stateLock.RLock()
	defer hw.stateLock.RUnlock()

	if hw.client == nil {
		return nil, accounts.ErrWalletClosed
	}

	secretData, ok := hw.accountsSecretMap[account.Address]
	if !ok {
		return nil, accounts.ErrUnknownAccount
	}

	key, err := hw.getPrivateKey(secretData)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key)

	// Depending on the presence of the chain ID, sign with EIP155 or homestead
	if chainID != nil && !tx.IsPrivate() {
		return types.SignTx(tx, types.NewEIP155Signer(chainID), key)
	}
	return types.SignTx(tx, types.HomesteadSigner{}, key)
}

func (hw *hashicorpWallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return hw.SignHash(account, hash)
}

func (hw *hashicorpWallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return hw.SignTx(account, tx, chainID, true)
}

func (hw *hashicorpWallet) read(path string, queryParams map[string][]string) (*api.Secret, error)  {
	return hw.client.Logical().ReadWithData(path, queryParams)
}

func (hw *hashicorpWallet) getAccount(secretData SecretData) (accounts.Account, error) {
	path, queryParams, err := secretData.toRequestData()

	if err != nil {
		return accounts.Account{}, err
	}

	secret, err := hw.read(path, queryParams)

	if err != nil {
		return accounts.Account{}, err
	}

	data := secret.Data["data"]

	m := data.(map[string]interface{})
	pubKey, ok := m[secretData.PublicKeyId]

	if !ok {
		//TODO change this error
		return accounts.Account{}, accounts.ErrUnknownAccount
	}

	pk, ok := pubKey.(string)

	if !ok {
		//TODO throw error as value retrieved from vault is not of type string
		panic("Retrieved key is not of type string")
	}

	if common.IsHexAddress(pk) {
		u := fmt.Sprintf("%v/v1/%v?version=%v", hw.clientData.Url, path, secretData.Version)

		url, err := parseURL(u)

		if err != nil {
			return accounts.Account{}, err
		}

		return accounts.Account{Address: common.HexToAddress(pk), URL: url}, nil
	}

	//TODO change error
	return accounts.Account{}, accounts.ErrUnknownAccount
}

// TODO Duplicated code from url.go
// parseURL converts a user supplied URL into the accounts specific structure.
func parseURL(url string) (accounts.URL, error) {
	parts := strings.Split(url, "://")
	if len(parts) != 2 || parts[0] == "" {
		return accounts.URL{}, errors.New("protocol scheme missing")
	}
	return accounts.URL {
		Scheme: parts[0],
		Path:   parts[1],
	}, nil
}


func (hw *hashicorpWallet) getPrivateKey(secretData SecretData) (*ecdsa.PrivateKey, error) {
	path, queryParams, err := secretData.toRequestData()

	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	secret, err := hw.read(path, queryParams)

	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	data := secret.Data["data"]

	m := data.(map[string]interface{})
	k, ok := m[secretData.PrivateKeyId]

	if !ok {
		//TODO change this error
		return &ecdsa.PrivateKey{}, accounts.ErrUnknownAccount
	}

	pk, ok := k.(string)

	if !ok {
		//TODO throw error as value retrieved from vault is not of type string
		panic("Not of type string")
	}
	fmt.Printf("Private key: %v\n", pk)

	key, err := crypto.HexToECDSA(pk)

	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	return key, nil
}

func (hw *hashicorpWallet) refresh() error {
	//TODO don't just overwrite, check existing accounts
	accts := make([]accounts.Account, len(hw.secrets))
	acctsScrtsMap := make(map[common.Address]SecretData)

	for i, secret := range hw.secrets {
		acct, err := hw.getAccount(secret)

		if err != nil {
			return err
		}

		accts[i] = acct
		acctsScrtsMap[acct.Address] = secret
	}

	hw.accounts = accts
	hw.accountsSecretMap = acctsScrtsMap

	return nil
}

//TODO duplicated code from keystore.go
// zeroKey zeroes a private key in memory.
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func GenerateAndStore(config HashicorpConfig) (common.Address, error) {
	hw, err := newHashicorpWallet(config.ClientData, config.Secrets)

	if err != nil {
		return common.Address{}, err
	}

	hw.Open("")

	if status, err := hw.Status(); err != nil {
		return common.Address{}, err
	} else if status == "Closed" {
		return common.Address{}, fmt.Errorf("error creating Vault client")
	}

	key, err := generateKey(rand.Reader)
	if err != nil {
		return common.Address{}, err
	}
	defer zeroKey(key)

	address, err := hw.storeKey(key)
	if err != nil {
		return common.Address{}, err
	}

	return address, nil
}

func generateKey(r io.Reader) (*ecdsa.PrivateKey, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), r)
	if err != nil {
		return nil, err
	}
	return privateKeyECDSA, nil
}

func (hw *hashicorpWallet) storeKey(key *ecdsa.PrivateKey) (common.Address, error) {
	address := crypto.PubkeyToAddress(key.PublicKey)
	addrHex := address.Hex()

	if strings.HasPrefix(addrHex, "0x") {
		addrHex = strings.Replace(addrHex, "0x", "", 1)
	}

	keyBytes := crypto.FromECDSA(key)
	keyHex := hex.EncodeToString(keyBytes)

	s := hw.secrets[0]

	path := fmt.Sprintf("%s/data/%s", s.SecretEngine, s.Name)

	data := make(map[string]interface{})
	data["data"] = map[string]interface{}{
		s.PublicKeyId : addrHex,
		s.PrivateKeyId: keyHex,
	}

	if _, err := hw.client.Logical().Write(path, data); err != nil {
		return common.Address{}, err
	}

	return address, nil
}