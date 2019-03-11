package vault

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
)

type hashicorpBackend struct {
	wallets []accounts.Wallet // A vault wallet contains all account keys stored in that particular vault and accessible with a particular auth token
}

type hashicorpData struct {
	clientData clientData
	secrets []secretData
}

func newHashicorpBackend(hashicorpData []hashicorpData) *hashicorpBackend {
	wallets := make([]accounts.Wallet, len(hashicorpData))
	for i, data := range hashicorpData {
		w := newHashicorpWallet(data.clientData, data.secrets)
		wallets[i] = w
	}

	return &hashicorpBackend{wallets}
}

func (hb *hashicorpBackend) Wallets() []accounts.Wallet {
	hb.refreshWallets()
	return hb.wallets
}

func (hb *hashicorpBackend) refreshWallets() {
	// Check which wallets have been added/dropped and raise corresponding events
	// Update hb.wallets with refreshed wallets
}

func (*hashicorpBackend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	panic("implement me")
}

