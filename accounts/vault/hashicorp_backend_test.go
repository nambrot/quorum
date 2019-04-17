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

func TestConstructorErrorCreatingWalletDoesNotPreventCreationOfOtherWallets(t *testing.T) {
	v := 2
	i := 2
	c := createValidAndInvalidWalletConfigs(v, i)
	b := NewHashicorpBackend(c)

	w := b.wallets

	if len(w) != v {
		t.Errorf("incorrect number of wallets created, want %v, got %v", v, len(w))
	}
}

func createValidAndInvalidWalletConfigs(valid, invalid int) []HashicorpWalletConfig {
	var c []HashicorpWalletConfig

	for i := 0; i < valid; i++ {
		c = append(c,
			HashicorpWalletConfig{
				Client: HashicorpClientConfig{Url: "http://client"},
			})
	}

	for i := 0; i < invalid; i++ {
		c = append(c,
			HashicorpWalletConfig{
				Client: HashicorpClientConfig{Url: "noscheme"},
		})
	}

	return c
}

func TestWalletsReturnsCopy(t *testing.T) {
	w1 := &vaultWallet{url: accounts.URL{"http", "vault1"}}
	w2 := &vaultWallet{url: accounts.URL{"http", "vault2"}}

	wallets := []accounts.Wallet{
		w1, w2,
	}

	b := hashicorpBackend{wallets: wallets}

	result := b.Wallets()

	if !reflect.DeepEqual(result, wallets) {
		t.Errorf("incorrect wallets returned from backend\nwant: %v\ngot : %v", wallets, result)
	}

	w3 := &vaultWallet{url: accounts.URL{"http", "vault3"}}

	result[0] = w3

	if !reflect.DeepEqual(b.wallets, wallets) {
		t.Errorf("changing the Wallets() return value should not alter the backend's wallets property\nwant: %v\ngot : %v", wallets, b.wallets)
	}
}

func TestSubscribe(t *testing.T) {
	b := hashicorpBackend{}
	c1 := make(chan accounts.WalletEvent)
	c2 := make(chan accounts.WalletEvent)

	b.Subscribe(c1)
	b.Subscribe(c2)

	w := &vaultWallet{}
	event := accounts.WalletEvent{Wallet: w, Kind: accounts.WalletArrived}
	go b.updateFeed.Send(event)

	fromSub := <-c1
	if !reflect.DeepEqual(fromSub, event) {
		t.Errorf("value from channel does not equal sent event\nwant: %v\ngot : %v", event, fromSub)
	}

	fromSub = <-c2
	if !reflect.DeepEqual(fromSub, event) {
		t.Errorf("value from channel does not equal sent event\nwant: %v\ngot : %v", event, fromSub)
	}
}
