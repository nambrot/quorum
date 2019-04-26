package vault

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/pkg/errors"
	"math/big"
	"reflect"
	"testing"
)

// mockVaultService provides a mockable vault service by allowing the user to define the functions that will be called for each of the vaultService interface's methods
type mockVaultService struct {
	statusMock func() (string, error)
	openMock func() error
	isOpenMock func() bool
	closeMock func() error
	getAccountsMock func() ([]accounts.Account, []error)
	getPrivateKeyMock func(account accounts.Account) (*ecdsa.PrivateKey, error)
	storeMock func(key *ecdsa.PrivateKey) (common.Address, error)
}

func (m mockVaultService) Status() (string, error) {
	return m.statusMock()
}

func (m mockVaultService) Open() error {
	return m.openMock()
}

func (m mockVaultService) IsOpen() bool {
	return m.isOpenMock()
}

func (m mockVaultService) Close() error {
	return m.closeMock()
}

func (m mockVaultService) GetAccounts() ([]accounts.Account, []error) {
	return m.getAccountsMock()
}

func (m mockVaultService) GetPrivateKey(account accounts.Account) (*ecdsa.PrivateKey, error) {
	return m.getPrivateKeyMock(account)
}

func (m mockVaultService) Store(key *ecdsa.PrivateKey) (common.Address, error) {
	return m.storeMock(key)
}

func TestConstructor(t *testing.T) {
	var f *event.Feed

	url := accounts.URL{Scheme: "http", Path: "client"}
	strUrl := url.String()

	client := HashicorpClientConfig{Url: strUrl}
	c := HashicorpWalletConfig{Client: client}

	w, err := NewHashicorpVaultWallet(c, f)

	if err != nil {
		t.Errorf("error creating wallet, err = %v", err)
	}

	if w.url != url {
		t.Errorf("wallet url incorrectly parsed from config\nwant: %v\ngot : %v ", url, w.url)
	}

	if w.updateFeed != f {
		t.Errorf("wallet not using provided event feed\nwant: %p\ngot : %p", f, w.updateFeed)
	}
}

func TestConstructorMalformedUrlDoesNotCreateWallet(t *testing.T) {
	var f *event.Feed
	client := HashicorpClientConfig{Url: "noscheme"}
	c := HashicorpWalletConfig{Client: client}

	w, err := NewHashicorpVaultWallet(c, f)

	if reflect.DeepEqual(*w, reflect.Zero(reflect.TypeOf(vaultWallet{}))) {
		t.Errorf("returned wallet is not zero value\nwant: %v\ngot : %v", vaultWallet{}, *w)
	}

	if err != malformedUrlErr {
		t.Errorf("want error: %v\ngot error: %v", malformedUrlErr, err)
	}
}

func TestConstructorNoUrlDoesNotCreateWallet(t *testing.T) {
	var f *event.Feed
	client := HashicorpClientConfig{}
	c := HashicorpWalletConfig{Client: client}

	w, err := NewHashicorpVaultWallet(c, f)

	if reflect.DeepEqual(*w, reflect.Zero(reflect.TypeOf(vaultWallet{}))) {
		t.Errorf("returned wallet is not zero value\nwant: %v\ngot : %v", vaultWallet{}, *w)
	}

	if err != noUrlErr {
		t.Errorf("want error: %v\ngot error: %v", noUrlErr, err)
	}
}

func TestUrlResultIsCopy(t *testing.T) {
	u := accounts.URL{Scheme: "http", Path: "client"}
	w := vaultWallet{url: u}

	result := w.URL()

	if result != u {
		t.Errorf("incorrect url returned\nwant: %v\ngot : %v", u, result)
	}
}

func TestStatus(t *testing.T) {
	status := "Some status"
	err := errors.New("some error")

	v := mockVaultService{
		statusMock: func() (string, error) {
			return status, err
		},
	}
	w := vaultWallet{vault: v}

	s, e := w.Status()

	if s != status {
		t.Errorf("incorrect status\nwant: %v\ngot : %v", status, s)
	}

	if e != err {
		t.Errorf("incorrect error\nwant: %v\ngot : %v", err, e)
	}
}

func TestOpenReturnsErrIfWalletAlreadyOpen(t *testing.T) {
	v := mockVaultService{
		isOpenMock: func() bool {
			return true
		},
	}
	w := vaultWallet{vault: v}

	if err := w.Open(""); err == nil || err != accounts.ErrWalletAlreadyOpen {
		t.Errorf("expected error\nwant: %v\ngot : %v", accounts.ErrWalletAlreadyOpen, err)
	}
}

func TestOpenReturnsErrorIfUnableToOpen(t *testing.T) {
	e := errors.New("some error")

	v := mockVaultService{
		isOpenMock: func() bool {
			return false
		},
		openMock: func() error {
			return e
		},
	}
	w := vaultWallet{vault: v}

	if err := w.Open(""); err == nil || err != e {
		t.Errorf("expected error\nwant: %v\ngot : %v", e, err)
	}
}

func TestOpenSendsToEventFeedIsSuccessful(t *testing.T) {
	v := mockVaultService{
		isOpenMock: func() bool {
			return false
		},
		openMock: func() error {
			return nil
		},
	}
	f := &event.Feed{}
	c := make(chan accounts.WalletEvent)
	f.Subscribe(c)
	w := vaultWallet{vault: v, updateFeed: f}

	err := w.Open("")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	got :=  <-c

	want := accounts.WalletEvent{
		Wallet: &w, Kind: accounts.WalletOpened,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("incorrect WalletEvent created\nwant: %v\ngot : %v", want, got)
	}
}

func TestCloseAccountsRemovedEvenIfServiceCloseFails(t *testing.T) {
	e := errors.New("some error")

	v := mockVaultService{
		closeMock: func() error {
			return e
		},
	}
	accts := []accounts.Account{
		{URL: accounts.URL{"http", "client"}},
	}
	w := vaultWallet{vault: v, accounts: accts}

	if w.accounts == nil {
		t.Errorf("want accounts in wallet before doing Close()")
	}

	err := w.Close()

	if err != e {
		t.Errorf("incorrect error\nwant: %v\ngot : %v", e, err)
	}

	if w.accounts != nil {
		t.Errorf("accounts not zeroed as part of Close()\nwant: %v\ngot : %v", nil, w.accounts)
	}
}

func TestAccountsReturnsCopy(t *testing.T) {
	accts := []accounts.Account{
		{URL: accounts.URL{Scheme: "http", Path: "client"}},
		{URL: accounts.URL{Scheme: "http", Path: "anotherclient"}},
	}

	errs := []error{
		errors.New("an error"),
	}

	v := mockVaultService{
		getAccountsMock: func() ([]accounts.Account, []error) {
			return accts, errs
		},
	}
	w := vaultWallet{vault: v}

	a := w.Accounts()

	if !reflect.DeepEqual(accts, a) {
		t.Errorf("incorrect accounts returned\nwant: %v\ngot : %v", accts, a)
	}

	a[1] = accounts.Account{URL: accounts.URL{Scheme: "http", Path: "edited"}}

	if !reflect.DeepEqual(w.accounts, accts) {
		t.Errorf("wallet's accounts field should not be changed by changing the return value of Accounts()\nwant: %v\ngot : %v", accts, w.accounts)
	}
}

func TestContainsMatchesWithSameAddressAndUrl(t *testing.T) {
	addr := common.StringToAddress("someaddress")
	url := accounts.URL{Scheme: "http", Path: "client"}

	v := mockVaultService{
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{
				{Address: addr, URL: url},
			}

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	toFind := accounts.Account{Address: addr, URL: url}

	if !w.Contains(toFind) {
		t.Errorf("wallet should contain account %v\nactually contains accounts: %v", toFind, w.accounts)
	}
}

func TestContainsMatchesWithAddressOnlyIfNoUrlProvided(t *testing.T) {
	addr := common.StringToAddress("someaddress")
	url := accounts.URL{Scheme: "http", Path: "client"}

	v := mockVaultService{
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{
				{Address: addr, URL: url},
			}

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	toFind := accounts.Account{Address: addr, URL: accounts.URL{}}

	if !w.Contains(toFind) {
		t.Errorf("wallet should contain account %v\nactually contains accounts: %v", toFind, w.accounts)
	}
}

func TestContainsDoesNotMatchIfSameUrlButDifferentAddress(t *testing.T) {
	url := accounts.URL{Scheme: "http", Path: "client"}

	v := mockVaultService{
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{
				{Address: common.StringToAddress("someaddress"), URL: url},
			}

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	toFind := accounts.Account{Address: common.StringToAddress("anotheraddress"), URL: accounts.URL{}}

	if w.Contains(toFind) {
		t.Errorf("Contains() returned true when address is different\nwallet shouldn't contain account %v\nactually contains accounts %v", toFind, w.accounts)
	}
}

func TestContainsDoesNotMatchIfDifferentUrlAndAddress(t *testing.T) {
	v := mockVaultService{
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{
				{Address: common.StringToAddress("someaddress"), URL: accounts.URL{Scheme: "http", Path: "client"}},
			}

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	toFind := accounts.Account{Address: common.StringToAddress("anotheraddress"), URL: accounts.URL{Scheme: "http", Path: "anotherclient"}}

	if w.Contains(toFind) {
		t.Errorf("Contains() returned true when address is different\nwallet shouldn't contain account %v\nactually contains accounts %v", toFind, w.accounts)
	}
}

func TestContainsMatchesWhenWalletContainsMoreThanOneAccount(t *testing.T) {
	v := mockVaultService{
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{
				{Address: common.StringToAddress("someaddress"), URL: accounts.URL{Scheme: "http", Path: "client"}},
				{Address: common.StringToAddress("anotheraddress"), URL: accounts.URL{Scheme: "http", Path: "anotherclient"}},
			}

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	toFind := accounts.Account{Address: common.StringToAddress("anotheraddress"), URL: accounts.URL{Scheme: "http", Path: "anotherclient"}}

	if !w.Contains(toFind) {
		t.Errorf("wallet should contain account %v\nactually contains accounts: %v", toFind, w.accounts)
	}
}

func TestDeriveNotSupported(t *testing.T) {
	w := vaultWallet{}
	acct, err := w.Derive(nil, true)

	if !reflect.DeepEqual(acct, reflect.Zero(reflect.TypeOf(accounts.Account{})).Interface()) {
		t.Errorf("want: %v\ngot : %v", accounts.Account{}, acct)
	}

	if err != accounts.ErrNotSupported {
		t.Errorf("want: %v\ngot : %v", accounts.ErrNotSupported, err)
	}
}

func TestSignHashReturnsErrorIfAccountNotKnownByWallet(t *testing.T) {
	v := mockVaultService{
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{
				{Address: common.StringToAddress("someaddress"), URL: accounts.URL{Scheme: "http", Path: "someclient"}},
			}

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	a := accounts.Account{Address: common.StringToAddress("anotheraddress"), URL: accounts.URL{Scheme: "http", Path: "anotherclient"}}

	signed, err := w.SignHash(a, []byte("somedata"))

	if signed != nil && err != accounts.ErrUnknownAccount {
		t.Errorf("incorrect return values when signing with unknown account\nwant: %v, %v\ngot : %v, %v", nil, accounts.ErrUnknownAccount,  signed, err)
	}
}

func TestSignHashReturnsErrorIfUnableToRetrieveKeyFromVault(t *testing.T) {
	e := errors.New("an error")
	acct := accounts.Account{}
	v := mockVaultService{
		getPrivateKeyMock: func(account accounts.Account) (*ecdsa.PrivateKey, error) {
			return nil, e
		},
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{ acct }

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	toSign := make([]byte, 32)

	result, err := w.SignHash(acct, toSign)

	if result != nil {
		t.Errorf("want: %v\ngot : %v", nil, result)
	}

	if err != e {
		t.Errorf("unexpected error\nwant: %v\ngot : %v", e, err)
	}
}

func TestSignHashSignsWithKeyThenKeyZeroed(t *testing.T) {
	k, err := crypto.GenerateKey()
	acct := accounts.Account{}
	v := mockVaultService{
		getPrivateKeyMock: func(account accounts.Account) (*ecdsa.PrivateKey, error) {
			return k, nil
		},
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{ acct }
			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	toSign := make([]byte, 32)

	want, err := crypto.Sign(toSign, k)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	got, err := w.SignHash(acct, toSign)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("incorrect signed result\nwant: %v\ngot : %v", want, got)
	}

	for b := range k.D.Bytes() {
		if b != 0 {
			t.Fatalf("private key not zeroed after sign: %v", k.D) // we do not need to check the other bytes if at least one is non-zero
		}
	}
}

func TestSignTxReturnsErrorIfAccountNotKnownByWallet(t *testing.T) {
	v := mockVaultService{
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{
				{Address: common.StringToAddress("someaddress"), URL: accounts.URL{Scheme: "http", Path: "someclient"}},
			}

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	a := accounts.Account{Address: common.StringToAddress("anotheraddress"), URL: accounts.URL{Scheme: "http", Path: "anotherclient"}}

	signed, err := w.SignTx(a, &types.Transaction{}, &big.Int{}, true)

	if signed != nil && err != accounts.ErrUnknownAccount {
		t.Errorf("incorrect return values when signing with unknown account\nwant: %v, %v\ngot : %v, %v", nil, accounts.ErrUnknownAccount,  signed, err)
	}
}

func TestSignTxReturnsErrorIfUnableToRetrieveKeyFromVault(t *testing.T) {
	e := errors.New("an error")
	acct := accounts.Account{}

	v := mockVaultService{
		getPrivateKeyMock: func(account accounts.Account) (*ecdsa.PrivateKey, error) {
			return nil, e
		},
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{ acct }

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	result, err := w.SignTx(acct, &types.Transaction{}, &big.Int{}, true)

	if result != nil {
		t.Errorf("want: %v\ngot : %v", nil, result)
	}

	if err != e {
		t.Errorf("unexpected error\nwant: %v\ngot : %v", e, err)
	}
}

func TestSignTxUsesHomesteadSignerIfChainIdNilAndPublicTxThenZeroesKey(t *testing.T) {
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Errorf("unexpected error: %v" , err)
	}
	acct := accounts.Account{}

	v := mockVaultService{
		getPrivateKeyMock: func(account accounts.Account) (*ecdsa.PrivateKey, error) {
			return k, nil
		},
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{ acct }

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	var chainID *big.Int
	chainID = nil

	toSign := &types.Transaction{}

	// create copy of tx to be signed. This will be used to create the expected signed tx.
	var toSignCpy types.Transaction
	toSignCpy = *toSign

	wantSigner := types.HomesteadSigner{}
	h := wantSigner.Hash(&toSignCpy)
	wantSig, err := crypto.Sign(h[:], k)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	want, err := toSignCpy.WithSignature(wantSigner, wantSig)

	got, err := w.SignTx(acct, toSign, chainID, true)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("incorrect signing response\nwant: %v\ngot : %v", want, got)
	}

	for b := range k.D.Bytes() {
		if b != 0 {
			t.Fatalf("private key not zeroed after sign: %v", k.D) // we do not need to check the other bytes if at least one is non-zero
		}
	}
}

func TestSignTxUsesHomesteadSignerIfChainIdNilAndPrivateTxThenZeroesKey(t *testing.T) {
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Errorf("unexpected error: %v" , err)
	}
	acct := accounts.Account{}

	v := mockVaultService{
		getPrivateKeyMock: func(account accounts.Account) (*ecdsa.PrivateKey, error) {
			return k, nil
		},
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{ acct }

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	var chainID *big.Int
	chainID = nil

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
	toSign.SetPrivate()

	// create copy of tx to be signed. This will be used to create the expected signed tx.
	var toSignCpy types.Transaction
	toSignCpy = *toSign

	wantSigner := types.HomesteadSigner{}
	h := wantSigner.Hash(&toSignCpy)
	wantSig, err := crypto.Sign(h[:], k)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	want, err := toSignCpy.WithSignature(wantSigner, wantSig)

	got, err := w.SignTx(acct, toSign, chainID, true)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("incorrect signing response\nwant: %v\ngot : %v", want, got)
	}

	for b := range k.D.Bytes() {
		if b != 0 {
			t.Fatalf("private key not zeroed after sign: %v", k.D) // we do not need to check the other bytes if at least one is non-zero
		}
	}
}

func TestSignTxUsesHomesteadSignerIfChainIdNonNilAndPrivateTxThenZeroesKey(t *testing.T) {
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Errorf("unexpected error: %v" , err)
	}
	acct := accounts.Account{}

	v := mockVaultService{
		getPrivateKeyMock: func(account accounts.Account) (*ecdsa.PrivateKey, error) {
			return k, nil
		},
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{ acct }

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	var chainID *big.Int
	chainID = big.NewInt(1337)

	toSign := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
	toSign.SetPrivate()

	// create copy of tx to be signed. This will be used to create the expected signed tx.
	var toSignCpy types.Transaction
	toSignCpy = *toSign

	wantSigner := types.HomesteadSigner{}
	h := wantSigner.Hash(&toSignCpy)
	wantSig, err := crypto.Sign(h[:], k)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	want, err := toSignCpy.WithSignature(wantSigner, wantSig)

	got, err := w.SignTx(acct, toSign, chainID, true)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("incorrect signing response\nwant: %v\ngot : %v", want, got)
	}

	for b := range k.D.Bytes() {
		if b != 0 {
			t.Fatalf("private key not zeroed after sign: %v", k.D) // we do not need to check the other bytes if at least one is non-zero
		}
	}
}

func TestSignTxUsesEIP155SignerIfChainIdNonNilAndPublicTxThenZeroesKey(t *testing.T) {
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Errorf("unexpected error: %v" , err)
	}
	acct := accounts.Account{}

	v := mockVaultService{
		getPrivateKeyMock: func(account accounts.Account) (*ecdsa.PrivateKey, error) {
			return k, nil
		},
		getAccountsMock: func() ([]accounts.Account, []error) {
			accts := []accounts.Account{ acct }

			return accts, nil
		},
	}
	w := vaultWallet{vault: v}

	var chainID *big.Int
	chainID = big.NewInt(1337)

	toSign := &types.Transaction{}

	// create copy of tx to be signed. This will be used to create the expected signed tx.
	var toSignCpy types.Transaction
	toSignCpy = *toSign

	wantSigner := types.NewEIP155Signer(chainID)
	h := wantSigner.Hash(&toSignCpy)
	wantSig, err := crypto.Sign(h[:], k)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	want, err := toSignCpy.WithSignature(wantSigner, wantSig)

	got, err := w.SignTx(acct, toSign, chainID, true)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("incorrect signing response\nwant: %v\ngot : %v", want, got)
	}

	for b := range k.D.Bytes() {
		if b != 0 {
			t.Fatalf("private key not zeroed after sign: %v", k.D) // we do not need to check the other bytes if at least one is non-zero
		}
	}
}

func TestStore(t *testing.T) {
	want := common.StringToAddress("anaddress")
	v := mockVaultService{
		storeMock: func(key *ecdsa.PrivateKey) (common.Address, error) {
			return want, nil
		},
	}
	w := vaultWallet{vault: v}

	k := &ecdsa.PrivateKey{}
	got, err := w.Store(k)

	if got != want {
		t.Errorf("incorrect address returned\nwant: %v\n got : %v", want, got)
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}