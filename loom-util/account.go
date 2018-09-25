package loomutil

import (
	"encoding/base64"

	"github.com/ethereum/go-ethereum/common"
	loom "github.com/loomnetwork/go-loom"
	"github.com/loomnetwork/go-loom/auth"
	"golang.org/x/crypto/ed25519"
)

// Account struct
type Account struct {
	PrivateKey       ed25519.PrivateKey
	PrivateKeyBase64 string
	PublicKey        ed25519.PublicKey
	PublicKeyBase64  string
	Address          loom.Address
	Signer           auth.Ed25519Signer
}

// NewAccount return *Account from PrivateKey
func NewAccount(chainID string, pri ed25519.PrivateKey) (*Account, error) {
	ret := &Account{}
	ret.PrivateKey = pri
	ret.PublicKey = ret.PrivateKey.Public().(ed25519.PublicKey)
	ret.PrivateKeyBase64 = base64.StdEncoding.EncodeToString(ret.PrivateKey)
	ret.PublicKeyBase64 = base64.StdEncoding.EncodeToString(ret.PublicKey)
	ret.Address = loom.Address{
		ChainID: chainID,
		Local:   loom.LocalAddressFromPublicKey(ret.PublicKey),
	}
	ret.Signer = *auth.NewEd25519Signer(ret.PrivateKey)

	return ret, nil
}

// NewAccountFromPrivateKeyBase64 return *Account from PrivateKeyBase64
func NewAccountFromPrivateKeyBase64(chainID string, priBase64 string) (*Account, error) {
	pri, err := base64.StdEncoding.DecodeString(priBase64)
	if err != nil {
		return nil, err
	}
	return NewAccount(chainID, pri)
}

// GenerateAccount generate new PrivateKey and return *Account
func GenerateAccount(chainID string) (*Account, error) {
	_, pri, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return NewAccount(chainID, pri)
}

// EthTypeAddress returns go-ethereum typed Address
func (a Account) EthTypeAddress() common.Address {
	return common.HexToAddress(a.Address.Local.String())
}
