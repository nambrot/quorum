package vault

import (
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/pkg/errors"
	"sort"
	"sync"
)

// hashicorpBackend is an accounts.Backend that handles all Hashicorp Vault wallets
type hashicorpBackend struct {
	stateLock sync.RWMutex
	wallets []accounts.Wallet // A vault wallet contains all account keys stored in that particular vault and accessible with a particular auth token
	updateFeed event.Feed
	updateScope event.SubscriptionScope
	hashicorpConfigs []HashicorpWalletConfig
}

// walletsByUrl implements the sort interface to enable the sorting of a slice of wallets by their urls
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

// NewHashicorpBackend is the hashicorpBackend constructor and initialises the new backend by creating a wallet for each the provided walletConfigs.
// The wallets are not opened and no secrets are retrieved from the vault.
func NewHashicorpBackend(walletConfigs []HashicorpWalletConfig) *hashicorpBackend {
	hb := &hashicorpBackend{hashicorpConfigs: walletConfigs}
	errs := hb.createWallets()

	for err := range errs {
		log.Warn("unable to create Hashicorp wallet", "err", err)
	}

	return hb
}

// createWallets creates wallets from the backend's wallet configs and updates the backend's wallets field with the result.
// The wallets are sorted alphabetically by their url.
func (hb *hashicorpBackend) createWallets() []error {
	hb.stateLock.Lock()
	defer hb.stateLock.Unlock()

	var errs []error
	var wallets []accounts.Wallet

	// The wallets for the keystore and hub backends can change frequently (e.g. files created/deleted in datadir, or USB devices connected/disconnected).  The Vault wallet configs can only be provided at startup - if the vault backend already has wallets then they do not need to be created again.
	// If there is an error creating the wallet for a particular config, the error is stored and the other wallets are attempted to be created.  All errors are then returned.
	if len(hb.wallets) == 0 {
		for _, hc := range hb.hashicorpConfigs {
			w, err := NewHashicorpVaultWallet(hc, &hb.updateFeed)
			if err != nil {
				errs = append(errs, errors.WithMessage(err, fmt.Sprintf("For Hashicorp client config with url %v", hc.Client.Url)))
				continue
			}

			wallets = append(wallets, w)

			//TODO create goroutine to periodically check vault for changes
		}

		sort.Sort(walletsByUrl(wallets))
		hb.wallets = wallets
	}

	return errs
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

func (hb *hashicorpBackend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	hb.stateLock.Lock()
	defer hb.stateLock.Unlock()

	// Subscribe the caller and track the subscriber count
	sub := hb.updateScope.Track(hb.updateFeed.Subscribe(sink))

	return sub
}
