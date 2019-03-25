package hashicorp

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"sync"
)

type hashicorpBackend struct {
	stateLock sync.RWMutex
	wallets []accounts.Wallet // A vault wallet contains all account keys stored in that particular vault and accessible with a particular auth token
	updateFeed event.Feed
	updateScope event.SubscriptionScope
	hashicorpConfigs []WalletConfig
}

func NewBackend(hashicorpConfigs []WalletConfig) *hashicorpBackend {
	hb := &hashicorpBackend{hashicorpConfigs: hashicorpConfigs}
	hb.refreshWallets()

	return hb
}

func (hb *hashicorpBackend) Wallets() []accounts.Wallet {
	// check connection to vault is still up before returning wallet
	// update list of accounts in wallets to cover the instances where secrets have been updated/deleted
	hb.stateLock.RLock()
	defer hb.stateLock.RUnlock()

	cpy := make([]accounts.Wallet, len(hb.wallets))
	copy(cpy, hb.wallets)

	return cpy
}

func (hb *hashicorpBackend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	hb.stateLock.Lock()
	defer hb.stateLock.Unlock()

	// Subscribe the caller and track the subscriber count
	sub := hb.updateScope.Track(hb.updateFeed.Subscribe(sink))

	return sub
}

func (hb *hashicorpBackend) refreshWallets() {
	// Check which wallets have been added/dropped and raise corresponding events
	// Update hb.wallets with refreshed wallets
	hb.stateLock.Lock()
	defer hb.stateLock.Unlock()

	var wallets []accounts.Wallet
	var events []accounts.WalletEvent

	// The wallets for the keystore and hub backends can change frequently (e.g. files created/deleted in datadir, or USB devices connected/disconnected).  The Vault wallets have to be defined as part of the start up config.  As a result we only need to refresh wallets once, on startup - if the vault backend already has wallets then we know the accounts have been retrieved from the vaults on startup so we do not need to check again
	if len(hb.wallets) == 0 {
		for _, hc := range hb.hashicorpConfigs {
			w, err := NewWallet(hc.Client, hc.Secrets, &hb.updateFeed)
			//TODO review how to handle and add contextual info to msgs
			if err != nil {
				log.Warn("Unable to create Hashicorp wallet", err)
				return
			}

			if err = w.refreshAccounts(); err != nil {
				log.Warn("Unable to refresh accounts")
				return
			}

			events = append(events, accounts.WalletEvent{w, accounts.WalletArrived})
			wallets = append(wallets, w)
		}

		for _, e := range events {
			hb.updateFeed.Send(e)
		}

		hb.wallets = wallets
	}

}