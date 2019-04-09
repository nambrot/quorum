package vault

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"sort"
	"sync"
)

type hashicorpBackend struct {
	stateLock sync.RWMutex
	wallets []accounts.Wallet // A vault wallet contains all account keys stored in that particular vault and accessible with a particular auth token
	updateFeed event.Feed
	updateScope event.SubscriptionScope
	hashicorpConfigs []HashicorpWalletConfig
}

type walletsByUrl []accounts.Wallet

func (w walletsByUrl) Len() int {
	return len(w)
}

func (w walletsByUrl) Less(i, j int) bool {
	return (w[i].URL()).Cmp(w[j].URL()) < 0
}

func (w walletsByUrl) Swap(i, j int) {
	w[i], w[j] = w[j], w[i]
}

func NewHashicorpBackend(hashicorpConfigs []HashicorpWalletConfig) *hashicorpBackend {
	hb := &hashicorpBackend{hashicorpConfigs: hashicorpConfigs}
	hb.createWallets()

	return hb
}

func (hb *hashicorpBackend) createWallets() {
	hb.stateLock.Lock()
	defer hb.stateLock.Unlock()

	var wallets []accounts.Wallet
	var events []accounts.WalletEvent

	// The wallets for the keystore and hub backends can change frequently (e.g. files created/deleted in datadir, or USB devices connected/disconnected).  The Vault wallets have to be defined as part of the start up config.  As a result we only need to refresh wallets once, on startup - if the vault backend already has wallets then we know the accounts have been retrieved from the vaults on startup so we do not need to check again
	if len(hb.wallets) == 0 {
		for _, hc := range hb.hashicorpConfigs {
			w, err := NewHashicorpVaultWallet(hc, &hb.updateFeed)
			//TODO review how to handle and add contextual info to msgs
			if err != nil {
				log.Warn("Unable to create Hashicorp wallet", err)
				return
			}

			events = append(events, accounts.WalletEvent{w, accounts.WalletArrived})
			wallets = append(wallets, w)

			//TODO create goroutine to periodically check vault for changes
		}

		for _, e := range events {
			hb.updateFeed.Send(e)
		}

		sort.Sort(walletsByUrl(wallets))
		hb.wallets = wallets
	}
}

func NewHashicorpVaultWallet(config HashicorpWalletConfig, updateFeed *event.Feed) (*vaultWallet, error) {
	url, err := parseURL(config.Client.Url)

	if err != nil {
		return &vaultWallet{}, err
	}

	s := NewHashicorpService(config.Client, config.Secrets)

	w := &vaultWallet{
		vault: s,
		url: url,
		updateFeed: updateFeed,
	}

	return w, nil
}

func (hb *hashicorpBackend) Wallets() []accounts.Wallet {
	// check connection to vault is still up before returning wallet
	// update list of accounts in wallets to cover the instances where secrets have been updated/deleted
	//hb.refreshWallets()

	hb.stateLock.RLock()
	defer hb.stateLock.RUnlock()
	cpy := make([]accounts.Wallet, len(hb.wallets))
	copy(cpy, hb.wallets)

	return cpy
}

//func (hb *hashicorpBackend) refreshWallets() {
//	// Check which wallets have been added/dropped and raise corresponding events
//	// Update hb.wallets with refreshed wallets
//	hb.stateLock.Lock()
//	defer hb.stateLock.Unlock()
//
//	//TODO Wallets should be created before being refreshed
//	if len(hb.wallets) == 0 {
//		return
//	}
//
//	for _, w := range hb.wallets {
//		hw, ok := w.(*hashicorpWallet)
//
//		if !ok {
//			log.Warn("Hashicorp backend contains Wallet of incompatible type %T", w) //TODO does log work in same way as Printf?
//			return
//		}
//
//		if err := hw.refreshAccounts(); err != nil {
//			log.Warn("Unable to refresh accounts", "err", err.Error())
//			return
//		}
//	}
//}

func (hb *hashicorpBackend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	hb.stateLock.Lock()
	defer hb.stateLock.Unlock()

	// Subscribe the caller and track the subscriber count
	sub := hb.updateScope.Track(hb.updateFeed.Subscribe(sink))

	return sub
}
