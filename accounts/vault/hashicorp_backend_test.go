package vault

import (
	"github.com/ethereum/go-ethereum/accounts"
	"reflect"
	"sort"
	"testing"
)



func TestWalletsByUrl(t *testing.T) {
	w1 := &vaultWallet{url: accounts.URL{Scheme: "http", Path: "localhost:8080"}}
	w2 := &vaultWallet{url: accounts.URL{Scheme: "http", Path: "localhost:9080"}}
	w3 := &vaultWallet{url: accounts.URL{Scheme: "http", Path: "anotherhost:8080"}}

	toSort := walletsByUrl {
		w1, w2, w3,
	}

	wantLen := 3
	if toSort.Len() != wantLen {
		t.Errorf("walletsByUrl Len() error, want %v got %v", wantLen, toSort.Len())
	}

	want := walletsByUrl {
		w3, w1, w2,
	}

	sort.Sort(toSort)

	if !reflect.DeepEqual(toSort, want) {
		t.Errorf("walletsByUrl sort error\nwant: %v\ngot : %v", want, toSort)
	}
}

func TestConstructorCreatesWallets(t *testing.T) {
	c := createWalletConfigs()
	b := NewHashicorpBackend(c)

	w := b.wallets

	if len(c) != len(w) {
		t.Errorf("incorrect number of wallets created, want %v, got %v", len(c), len(w))
	}
}

func createWalletConfigs() []HashicorpWalletConfig {
	c := make([]HashicorpClientConfig, 2)
	c[0] = HashicorpClientConfig{Url: "http://client1"}
	c[1] = HashicorpClientConfig{Url: "http://client2"}

	s := make([]HashicorpSecret, 3)
	s[0] = HashicorpSecret{Name: "secret1"}
	s[1] = HashicorpSecret{Name: "secret2"}
	s[2] = HashicorpSecret{Name: "secret3"}

	 return []HashicorpWalletConfig{
		{ Client: c[0], Secrets: s[:2] },
		{ Client: c[1], Secrets: s[2:3] },
	}
}