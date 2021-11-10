package util

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/wyrepo/wuyou-crypto-go/paillier/key"
	"github.com/wyrepo/wuyou-crypto-go/paillier/num"
	"math/big"
)

// Paillier.Int to Hex String
func IntToHexStr(value *num.Int) (string, error) {
	if value == nil {
		return "", errors.New("value (*Paillier.Int) for converting is nil")
	}
	cipher := value.Cipher
	if cipher == nil {
		return "", errors.New("cipher (*big.Int) for converting is nil")
	}
	bytes := cipher.Bytes()
	return hex.EncodeToString(bytes), nil
}

// Hex String to Paillier.Int
func HexStrToInt(pk *key.PublicKey, s string) (*num.Int, error) {
	if pk == nil {
		return nil, errors.New("public key is nil")
	}
	if s == "" {
		return nil, errors.New("hex string is nil")
	}
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	v := &big.Int{}
	v.SetBytes(bytes)
	return &num.Int{Cipher: v, PublicKey: pk}, nil
}

func WritePublicKeyToPem(key *key.PublicKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("public key is nil")
	}
	bytes, err := MarshalPublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	pkPem := pem.EncodeToMemory(block)
	return pkPem, nil
}

func WritePrivateKeyToPem(key *key.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("private key is nil")
	}
	var block *pem.Block
	bytes, err := MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	block = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}
	skPem := pem.EncodeToMemory(block)
	return skPem, nil
}

func ReadPublicKeyFromPem(pkPem []byte) (*key.PublicKey, error) {
	if pkPem == nil || len(pkPem) <= 0 {
		return nil, errors.New("public key is nil or empty")
	}
	block, rest := pem.Decode(pkPem)
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after public key")
	}
	if block == nil {
		return nil, errors.New("x509: block data is nil")
	}
	bytes := block.Bytes
	if bytes == nil || len(bytes) <= 0 {
		return nil, errors.New("x509: block data is empty")
	}
	pk, err := UnmarshalPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func ReadPrivateKeyFromPem(skPem []byte) (*key.PrivateKey, error) {
	if skPem == nil || len(skPem) <= 0 {
		return nil, errors.New("private key is nil or empty")
	}
	block, rest := pem.Decode(skPem)
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after private key")
	}
	if block == nil {
		return nil, errors.New("x509: block data is nil")
	}
	bytes := block.Bytes
	if bytes == nil || len(bytes) <= 0 {
		return nil, errors.New("x509: block data is empty")
	}
	sk, err := UnmarshalPrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func MarshalPublicKeyHex(pk *key.PublicKey) (string, error) {
	bytes, err := MarshalPublicKey(pk)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func MarshalPublicKey(pk *key.PublicKey) ([]byte, error) {
	// just record Length and N of PublicKey
	bytes, err := asn1.Marshal(key.PublicKeyInfo{
		Length: pk.Length,
		N:      pk.N,
	})
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func MarshalPrivateKey(sk *key.PrivateKey) ([]byte, error) {
	// just record Length, L, N and Threshold
	bytes, err := asn1.Marshal(key.PrivateKeyInfo{
		Length:    sk.Length,
		L:         sk.L,
		N:         sk.PublicKey.N,
		Threshold: sk.Threshold,
	})
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func UnmarshalPublicKeyHex(asn1Hex string) (*key.PublicKey, error) {
	asn1Data, err := hex.DecodeString(asn1Hex)
	if err != nil {
		return nil, err
	}
	return UnmarshalPublicKey(asn1Data)
}

func UnmarshalPublicKey(asn1Data []byte) (*key.PublicKey, error) {
	info := new(key.PublicKeyInfo)
	rest, err := asn1.Unmarshal(asn1Data, info)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after public key")
	}
	if info.N.Sign() <= 0 {
		return nil, errors.New("x509: key modulus is not a positive number")
	}
	if info.Length <= 0 {
		return nil, errors.New("x509: key length is not a positive number")
	}
	// restore PublicKey from Length and N
	one := big.NewInt(1)
	pk := &key.PublicKey{
		Length: info.Length,
		N:      info.N,
		NSq:    new(big.Int).Mul(info.N, info.N),
		G:      new(big.Int).Add(info.N, one),
	}
	return pk, nil
}

func UnmarshalPrivateKey(asn1Data []byte) (*key.PrivateKey, error) {
	info := new(key.PrivateKeyInfo)
	rest, err := asn1.Unmarshal(asn1Data, info)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after private key")
	}
	if info.N.Sign() <= 0 || info.L.Sign() <= 0 {
		return nil, errors.New("x509: key modulus is not a positive number")
	}
	if info.Length <= 0 {
		return nil, errors.New("x509: key length is not a positive number")
	}
	// restore PublicKey from Length and N
	one := big.NewInt(1)
	pk := &key.PublicKey{
		Length: info.Length,
		N:      info.N,
		NSq:    new(big.Int).Mul(info.N, info.N),
		G:      new(big.Int).Add(info.N, one),
	}
	// restore PrivateKey from Length, L and Threshold
	sk := &key.PrivateKey{
		Length:    info.Length,
		PublicKey: pk,
		L:         info.L,
		U:         new(big.Int).ModInverse(info.L, info.N),
		Threshold: info.Threshold,
	}
	return sk, nil
}
