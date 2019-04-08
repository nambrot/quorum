package vault

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"io"
	"math/big"
	"strings"
	"sync"
)

type vaultWallet struct {
	stateLock         sync.RWMutex  // Protects read and write access to the wallet struct fields
	vault             VaultService
	url               accounts.URL
	accounts          []accounts.Account
	updateFeed        *event.Feed
	logger            log.Logger
}

type VaultService interface {
	Status() (string, error)
	Open() error
	Close() error
	GetPrivateKey(account accounts.Account) (*ecdsa.PrivateKey, error)
	Store(key *ecdsa.PrivateKey) (common.Address, error)
}

func (w *vaultWallet) URL() accounts.URL {
	return w.url
}

func (w *vaultWallet) Status() (string, error) {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	return w.vault.Status()
}

// Open implements accounts.Wallet, creating an authenticated Client and making it accessible to the wallet to enable vault operations.
//
// If Approle credentials have been provided these will be used to authenticate the Client with the vault, else the Token will be used.
//
// The passphrase arg is not used and this method does not retrieve any secrets from the vault.
func (w *vaultWallet) Open(passphrase string) error {
	if err := w.vault.Open(); err != nil {
		return err
	}

	w.updateFeed.Send(
		accounts.WalletEvent{w, accounts.WalletOpened},
	)

	return nil
}

// Close implements accounts.Wallet, clearing the state of the wallet and removing the vault Client so vault operations can no longer be carried out.
func (w *vaultWallet) Close() error {
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	w.accounts = nil
	w.accountsSecretMap = nil

	return w.vault.Close()
}

// Account implements accounts.Wallet, returning the accounts specified in config that are stored in the vault.  refreshAccounts() retrieves the list of accounts from the vault and so must have been called prior to this method in order to return a non-empty slice
func (w *vaultWallet) Accounts() []accounts.Account {
	//TODO mutex?
	err := w.refreshAccounts()

	if err != nil {
		w.logger.Error("Unable to get accounts", "err", err)
	}

	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	cpy := make([]accounts.Account, len(w.accounts))
	copy(cpy, w.accounts)

	return cpy
}

// Contains implements accounts.Wallet, returning whether a particular account is managed by this wallet.
func (w *vaultWallet) Contains(account accounts.Account) bool {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	for _, wltAcct := range w.accounts {
		if wltAcct.Address == account.Address && (account.URL == accounts.URL{} || wltAcct.URL == account.URL) {
			return true
		}
	}

	return false
}

// Derive implements accounts.Wallet, but is a noop for Vault wallets since these have no notion of hierarchical account derivation.
func (*vaultWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, accounts.ErrNotSupported
}

// SelfDerive implements accounts.Wallet, but is a noop for Vault wallets since these have no notion of hierarchical account derivation.
func (w *vaultWallet) SelfDerive(base accounts.DerivationPath, chain ethereum.ChainStateReader) {}

func (w *vaultWallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	key, err := w.vault.GetPrivateKey(account)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key)

	return crypto.Sign(hash, key)
}

func (w *vaultWallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int, isQuorum bool) (*types.Transaction, error) {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	key, err := w.vault.GetPrivateKey(account)
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

func (w *vaultWallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return w.SignHash(account, hash)
}

func (w *vaultWallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.SignTx(account, tx, chainID, true)
}

func (w *vaultWallet) read(path string, queryParams map[string][]string) (*api.Secret, error)  {
	hw.stateLock.RLock()
	defer hw.stateLock.RUnlock()

	return hw.client.Logical().ReadWithData(path, queryParams)
}

type hashicorpError struct {
	msg       string
	secret    Secret
	walletUrl accounts.URL
	err       error
}

func (e hashicorpError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s, %v: wallet %v, secret %v", e.msg, e.err, e.walletUrl, e.secret)
	}

	return fmt.Sprintf("%s: wallet %v, secret %v", e.msg, e.walletUrl, e.secret)
}

func (hw *hashicorpWallet) getAccount(secretData Secret) (accounts.Account, error) {
	path, queryParams, err := secretData.toRequestData()

	if err != nil {
		return accounts.Account{}, hashicorpError{msg: "unable to get secret URL from data", secret: secretData, err: err}
	}

	secret, err := hw.read(path, queryParams)
	defer zeroSecret(secret)

	if err != nil {
		return accounts.Account{}, hashicorpError{"unable to retrieve secret from vault", secretData, hw.url, err}
	}

	data := secret.Data["data"]
	defer zeroSecretData(&data)

	m := data.(map[string]interface{})
	acct, ok := m[secretData.AccountID]

	if !ok {
		return accounts.Account{}, hashicorpError{"no value found in vault with provided AccountID", secretData, hw.url,nil}
	}

	strAcct, ok := acct.(string)

	if !ok {
		return accounts.Account{}, hashicorpError{"AccountID value in vault is not plain string", secretData, hw.url,nil}
	}

	if !common.IsHexAddress(strAcct) {
		return accounts.Account{}, hashicorpError{"unable to get account from vault", secretData, hw.url, nil}
	}

	u := fmt.Sprintf("%v/v1/%v?version=%v", hw.clientData.Url, path, secretData.Version)
	url, err := parseURL(u)

	if err != nil {
		return accounts.Account{}, hashicorpError{"unable to create account URL", secretData, hw.url, err}
	}

	return accounts.Account{Address: common.HexToAddress(strAcct), URL: url}, nil
}

func zeroSecretData(data *interface{}) {
	data = nil
}

func zeroSecret(secret *api.Secret) {
	secret = nil
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


func (hw *hashicorpWallet) getPrivateKey(secretData Secret) (*ecdsa.PrivateKey, error) {
	path, queryParams, err := secretData.toRequestData()

	if err != nil {
		return &ecdsa.PrivateKey{}, hashicorpError{msg: "unable to get secret URL from data", secret: secretData, err: err}
	}

	secret, err := hw.read(path, queryParams)
	defer zeroSecret(secret)

	if err != nil {
		return &ecdsa.PrivateKey{}, hashicorpError{"unable to retrieve secret from vault", secretData, hw.url, err}
	}

	data := secret.Data["data"]
	defer zeroSecretData(&data)

	m := data.(map[string]interface{})
	k, ok := m[secretData.KeyID]

	if !ok {
		return &ecdsa.PrivateKey{}, hashicorpError{"no value found in vault with provided KeyID", secretData, hw.url,nil}
	}

	strK, ok := k.(string)

	if !ok {
		return &ecdsa.PrivateKey{}, hashicorpError{"KeyID value in vault is not plain string", secretData, hw.url,nil}
	}

	key, err := crypto.HexToECDSA(strK)

	if err != nil {
		return &ecdsa.PrivateKey{}, hashicorpError{"", secretData, hw.url, err}
	}

	return key, nil
}

func (hw *hashicorpWallet) refreshAccounts() error {
	// All accounts have already been retrieved so we do not need to retrieve them again
	if len(hw.accounts) == len(hw.secrets) {
		return nil
	}

	if status, err := hw.Status(); status == walletClosed {
		return errors.New("Wallet closed")
	} else if err != nil {
		return err
	}

	accts := make([]accounts.Account, len(hw.secrets))
	acctsScrtsMap := make(map[common.Address]Secret)

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

// zeroKey zeroes a private key in memory.
//TODO duplicated code from keystore.go
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func GenerateAndStore(config WalletConfig) (common.Address, error) {
	hw, err := NewWallet(config.Client, config.Secrets, &event.Feed{})

	if err != nil {
		return common.Address{}, err
	}

	err = hw.Open("")

	if err != nil {
		return common.Address{}, err
	}

	if status, err := hw.Status(); err != nil {
		return common.Address{}, err
	} else if status != walletOpen {
		return common.Address{}, fmt.Errorf("error creating Vault client, %v", status)
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
		s.AccountID: addrHex,
		s.KeyID:     keyHex,
	}

	if _, err := hw.client.Logical().Write(path, data); err != nil {
		return common.Address{}, hashicorpError{"unable to write secret to vault", s, hw.url, err}
	}

	return address, nil
}