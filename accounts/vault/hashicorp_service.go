package vault

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"os"
	"sort"
	"strings"
	"sync"
)

type hashicorpService struct {
	clientFactory        clientDelegateFactory
	secrets              []HashicorpSecret
	stateLock            sync.RWMutex
	clientConfig         HashicorpClientConfig
	client               clientDelegate
	acctSecretsByAddress map[common.Address][]acctAndSecret // The same address may be provided in more than one way (e.g. by specifying v0 and a specific version which happens to be the latest version).  As a result multiple secrets may be defined for the same address
}

type clientDelegateFactory func() (clientDelegate, error)

func defaultClientDelegateFactory() (clientDelegate, error) {
	conf := api.DefaultConfig()
	client, err := api.NewClient(conf)

	if err != nil {
		return nil, err
	}

	return defaultClientDelegate{client}, nil
}

type clientDelegate interface {
	Logical() logicalDelegate
	Sys() sysDelegate
	SetAddress(addr string) error
	SetToken(v string)
	ClearToken()
}

type logicalDelegate interface{
	ReadWithData(path string, data map[string][]string) (*api.Secret, error)
	Write(path string, data map[string]interface{}) (*api.Secret, error)
}

type sysDelegate interface{
	Health() (*api.HealthResponse, error)
}

type defaultClientDelegate struct {
	*api.Client
}

func (cd defaultClientDelegate) Logical() logicalDelegate {
	return cd.Client.Logical()
}

func (cd defaultClientDelegate) Sys() sysDelegate {
	return cd.Client.Sys()
}

type acctAndSecret struct {
	acct accounts.Account
	secret HashicorpSecret
}

//TODO duplicated code from account_cache.go
type accountsByUrl []accounts.Account

func (a accountsByUrl) Len() int {
	return len(a)
}

func (a accountsByUrl) Less(i, j int) bool {
	return (a[i].URL).Cmp(a[j].URL) < 0
}

func (a accountsByUrl) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func newHashicorpService(clientConfig HashicorpClientConfig, secrets []HashicorpSecret) vaultService {
	return &hashicorpService{
		clientFactory: defaultClientDelegateFactory,
		clientConfig:  clientConfig,
		secrets:       secrets,
	}
}

const (
	walletClosed = "Closed"
	vaultUninitialised = "Vault uninitialised"
	vaultSealed = "Vault sealed"
	healthcheckFailed = "Vault healthcheck failed"
	walletOpen = "Open, vault initialised and unsealed"
)

func (s *hashicorpService) Status() (string, error) {
	s.stateLock.RLock()
	defer s.stateLock.RUnlock()

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

func (s *hashicorpService) IsOpen() bool {
	s.stateLock.RLock()
	defer s.stateLock.RUnlock()

	return s.client != nil
}

const (
	VaultRoleId   = "VAULT_ROLE_ID"
	VaultSecretId = "VAULT_SECRET_ID"
)

var (
	cannotAuthenticateErr = fmt.Errorf("Unable to authenticate client.  Set the %v and %v env vars to use AppRole authentication.  Set %v env var to use Token authentication", VaultRoleId, VaultSecretId, api.EnvVaultToken)

	approleAuthenticationErr = fmt.Errorf("both %q and %q environment variables must be set to use Approle authentication", VaultRoleId, VaultSecretId)
)

func (s *hashicorpService) Open() error {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	// If the environment variable `VAULT_TOKEN` is present, the token will be automatically added to the created client

	client, err := s.clientFactory()

	if err != nil {
		return err
	}

	if err := client.SetAddress(s.clientConfig.Url); err != nil {
		return err
	}

	s.client = client

	// If the roleID and secretID environment variables are present, these will be used to authenticate the client and replace the default VAULT_TOKEN value
	// As using Approle is preferred over using the standalone token, an error will be returned if only one of these environment variables is set
	roleId, rIdOk := os.LookupEnv(VaultRoleId)
	secretId, sIdOk := os.LookupEnv(VaultSecretId)
	t, tOk := os.LookupEnv(api.EnvVaultToken)

	fmt.Println(t)

	if !(rIdOk || sIdOk || tOk) {
		return cannotAuthenticateErr
	}

	if rIdOk != sIdOk {
		return approleAuthenticationErr
	}

	if rIdOk && sIdOk {
		authData := map[string]interface{} {"role_id": roleId, "secret_id": secretId}

		if s.clientConfig.Approle == "" {
			s.clientConfig.Approle = "approle"
		}

		authResponse, err := s.client.Logical().Write(fmt.Sprintf("auth/%s/login", s.clientConfig.Approle), authData)

		if err != nil {
			return err
		}

		token := authResponse.Auth.ClientToken
		s.client.SetToken(token)
	}

	return nil
}

func (s *hashicorpService) Close() error {
	if !s.IsOpen() {
		return nil
	}

	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	s.client.ClearToken()
	s.client = nil
	s.acctSecretsByAddress = nil

	return nil
}

func (s *hashicorpService) GetAccounts() ([]accounts.Account, []error) {
	if status, err := s.Status(); status == walletClosed {
		return nil, []error{errors.New("Wallet closed")}
	} else if err != nil {
		return nil, []error{err}
	}

	acctSecretsByAddress := make(map[common.Address][]acctAndSecret)
	var accts []accounts.Account

	// If a secret is not found in the vault we want to continue checking the other secrets before returning from this func
	var errs []error

	s.stateLock.RLock()
	for _, secret := range s.secrets {
		url, err := s.getAccountUrl(secret)

		if err != nil {
			errs = append(errs, errors.WithMessage(err, fmt.Sprintf("error getting account url for %+v", secret)))
			continue
		}

		addr, err := s.getAddress(secret)

		if err != nil {
			errs = append(errs, errors.WithMessage(err, fmt.Sprintf("error getting address for account %v", url)))
			continue
		}

		acctSecret := acctAndSecret{acct: accounts.Account{Address: addr, URL: url}, secret: secret}

		acctSecretsByAddress[addr] = append(acctSecretsByAddress[addr], acctSecret)
		accts = append(accts, accounts.Account{Address: addr, URL: url})
	}
	s.stateLock.RUnlock()

	s.stateLock.Lock()
	s.acctSecretsByAddress = acctSecretsByAddress
	s.stateLock.Unlock()

	sort.Sort(accountsByUrl(accts))

	return accts, errs
}

func (s *hashicorpService) getAccountUrl(secret HashicorpSecret) (accounts.URL, error) {
	path, _, err := secret.toRequestData()

	if err != nil {
		return accounts.URL{}, errors.WithMessage(err, "unable to get secret URL from data")
	}

	s.stateLock.RLock()
	defer s.stateLock.RUnlock()

	u := fmt.Sprintf("%v/v1/%v?version=%v", s.clientConfig.Url, path, secret.Version)
	url, err := parseURL(u)

	if err != nil {
		return accounts.URL{}, errors.WithMessage(err, "unable to create account URL")
	}

	return url, nil
}

func (s *hashicorpService) getAddress(secret HashicorpSecret) (common.Address, error) {
	path, queryParams, err := secret.toRequestData()

	if err != nil {
		return common.Address{}, errors.WithMessage(err, "unable to get secret URL from data")
	}

	s.stateLock.RLock()
	vaultResponse, err := s.client.Logical().ReadWithData(path, queryParams)
	s.stateLock.RUnlock()

	if err != nil {
		return common.Address{}, errors.WithMessage(err, "unable to retrieve secret from vault")
	}

	data := vaultResponse.Data["data"]

	m := data.(map[string]interface{})
	acct, ok := m[secret.AccountID]

	if !ok {
		return common.Address{}, fmt.Errorf("no value found in vault with provided AccountID %v", secret.AccountID)
	}

	strAcct, ok := acct.(string)

	if !ok {
		return common.Address{}, errors.New("AccountID value in vault is not plain string")
	}

	if !common.IsHexAddress(strAcct) {
		return common.Address{}, errors.New("value in vault is not a valid hex-encoded Ethereum address")
	}

	return common.HexToAddress(strAcct), nil
} 

func (s *hashicorpService) GetPrivateKey(account accounts.Account) (*ecdsa.PrivateKey, error) {
	s.stateLock.RLock()
	defer s.stateLock.RUnlock()

	acctAndSecrets, ok := s.acctSecretsByAddress[account.Address]

	if !ok {
		return &ecdsa.PrivateKey{}, accounts.ErrUnknownAccount
	}

	// if provided account has empty url then take first acct found for this address, else search for acct from vault that has the same url
	var secret HashicorpSecret
	for _, as := range acctAndSecrets {
		if account.URL == (accounts.URL{}) || account.URL == as.acct.URL {
			secret = as.secret
			break
		}
	}

	if secret == (HashicorpSecret{}) {
		return &ecdsa.PrivateKey{}, accounts.ErrUnknownAccount
	}

	path, queryParams, err := secret.toRequestData()

	if err != nil {
		return &ecdsa.PrivateKey{}, errors.WithMessage(err, "unable to get secret URL from data")
	}

	vaultResponse, err := s.client.Logical().ReadWithData(path, queryParams)

	if err != nil {
		return &ecdsa.PrivateKey{}, errors.WithMessage(err, "unable to retrieve secret from vault")
	}

	data, ok := vaultResponse.Data["data"]
	if !ok {
		return &ecdsa.PrivateKey{}, errors.New("vault response does not contain 'data' field")
	}

	m := data.(map[string]interface{})
	k, ok := m[secret.KeyID]

	if !ok {
		return &ecdsa.PrivateKey{}, fmt.Errorf("no value found in vault with provided KeyID %v", secret.KeyID)
	}

	strK, ok := k.(string)

	if !ok {
		return &ecdsa.PrivateKey{}, errors.New("KeyID value in vault is not plain string")
	}

	key, err := crypto.HexToECDSA(strK)

	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	return key, nil
}

func (s *hashicorpService) Store(key *ecdsa.PrivateKey) (common.Address, error) {
	address := crypto.PubkeyToAddress(key.PublicKey)
	addrHex := address.Hex()

	if strings.HasPrefix(addrHex, "0x") {
		addrHex = strings.Replace(addrHex, "0x", "", 1)
	}

	keyBytes := crypto.FromECDSA(key)
	keyHex := hex.EncodeToString(keyBytes)

	s.stateLock.RLock()
	defer s.stateLock.RUnlock()
	secret := s.secrets[0]

	path := fmt.Sprintf("%s/data/%s", secret.SecretEngine, secret.Name)

	data := make(map[string]interface{})
	data["data"] = map[string]interface{}{
		secret.AccountID: addrHex,
		secret.KeyID:     keyHex,
	}

	if _, err := s.client.Logical().Write(path, data); err != nil {
		return common.Address{}, errors.WithMessage(err, "unable to write secret to vault")
	}

	return address, nil
}
