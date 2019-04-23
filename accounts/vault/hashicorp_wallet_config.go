package vault

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"strconv"
)

type HashicorpWalletConfig struct {
	Client HashicorpClientConfig `toml:",omitempty"`
	Secrets    []HashicorpSecret     `toml:",omitempty"`
}

type HashicorpClientConfig struct {
	Url        string `toml:",omitempty"`
	Approle    string `toml:",omitempty"`
	CaCert     string `toml:",omitempty"`
	ClientCert string `toml:",omitempty"`
	ClientKey  string `toml:",omitempty"`
}

type HashicorpSecret struct {
	Name         string `toml:",omitempty"`
	SecretEngine string `toml:",omitempty"`
	Version      int    `toml:",omitempty"`
	AccountID    string `toml:",omitempty"`
	KeyID        string `toml:",omitempty"`
}

func (s HashicorpSecret) toRequestData() (string, map[string][]string, error) {
	path := fmt.Sprintf("%s/data/%s", s.SecretEngine, s.Name)

	queryParams := make(map[string][]string)
	if s.Version < 0 {
		return "", nil, fmt.Errorf("Hashicorp Vault secret version must be integer >= 0")
	}
	queryParams["version"] = []string{strconv.Itoa(s.Version)}

	return path, queryParams, nil
}

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
