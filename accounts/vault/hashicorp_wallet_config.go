package vault

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/pkg/errors"
	"strconv"
)

// HashicorpWalletConfig defines the configuration values required to create a client for the Vault and to define the secrets that should be read from/written to
type HashicorpWalletConfig struct {
	Client HashicorpClientConfig `toml:",omitempty"`
	Secrets    []HashicorpSecret     `toml:",omitempty"`
}

// HashicorpClientConfig defines the configuration values required by the vaultWallet to create a client to the Hashicorp Vault
type HashicorpClientConfig struct {
	Url          string `toml:",omitempty"`
	Approle      string `toml:",omitempty"`
	CaCert       string `toml:",omitempty"`
	ClientCert   string `toml:",omitempty"`
	ClientKey    string `toml:",omitempty"`
	EnvVarPrefix string `toml:",omitempty"`
}

// HashicorpSecret defines the configuration values required to read/write to a secret stored in a Hashicorp Vault
type HashicorpSecret struct {
	Name         string `toml:",omitempty"`
	SecretEngine string `toml:",omitempty"`
	Version      int    `toml:",omitempty"`
	AccountID    string `toml:",omitempty"`
	KeyID        string `toml:",omitempty"`
}

// toRequestData converts the fields of a HashicorpSecret into the relevant formats required to make a read/write request to the vault
//
// path defines URL path made up of the secret name and secret engine name
//
// queryParams includes the version of the secret
func (s HashicorpSecret) toRequestData() (path string, queryParams map[string][]string, err error) {
	path = fmt.Sprintf("%s/data/%s", s.SecretEngine, s.Name)

	queryParams = make(map[string][]string)
	if s.Version < 0 {
		return "", nil, fmt.Errorf("Hashicorp Vault secret version must be integer >= 0")
	}
	queryParams["version"] = []string{strconv.Itoa(s.Version)}

	return path, queryParams, nil
}

// GenerateAndStore creates and opens a new HashicorpVaultWallet from the provided config, generates a secp256k1 key and stores the key in the vault defined in the provided config.
//
// The length of the HashicorpSecret slice in the config should be 1 as the generated key will be stored in only this secret.  Any other secrets will be ignored.
func GenerateAndStore(config HashicorpWalletConfig) (common.Address, error) {
	w, err := NewHashicorpVaultWallet(config, &event.Feed{})

	if err != nil {
		return common.Address{}, err
	}

	err = w.Open("")

	if err != nil {
		return common.Address{}, err
	}

	if status, err := w.Status(); err != nil {
		return common.Address{}, err
	} else if status != walletOpen {
		return common.Address{}, fmt.Errorf("error creating Vault client, %v", status)
	}

	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return common.Address{}, err
	}
	defer zeroKey(key)

	address, err := w.Store(key)
	if err != nil {
		return common.Address{}, err
	}

	return address, nil
}
