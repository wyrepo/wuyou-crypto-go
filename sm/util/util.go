package util

import (
	"crypto"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm2"
	"github.com/wyrepo/wuyou-crypto-go/sm/x509"
	"io/ioutil"
)

func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (*sm2.PrivateKey, error) {
	return x509.ReadPrivateKeyFromPem(privateKeyPem, pwd)
}

func ReadPrivateKeyFromPemFile(filePath string, pwd []byte) (*sm2.PrivateKey, error) {
	privateKeyPem, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return x509.ReadPrivateKeyFromPem(privateKeyPem, pwd)
}

func WritePrivateKeyToPem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	return x509.WritePrivateKeyToPem(key, pwd)
}

func WritePrivateKeyToPemFile(filePath string, key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	privateKeyToPem, err := x509.WritePrivateKeyToPem(key, pwd)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(filePath, privateKeyToPem, 0644)
	if err != nil {
		return nil, err
	}
	return privateKeyToPem, nil
}

func ReadPublicKeyFromPem(publicKeyPem []byte) (*sm2.PublicKey, error) {
	return x509.ReadPublicKeyFromPem(publicKeyPem)
}

func ReadPublicKeyFromPemFile(filePath string) (*sm2.PublicKey, error) {
	publicKeyPem, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return x509.ReadPublicKeyFromPem(publicKeyPem)
}

func WritePublicKeyToPem(key *sm2.PublicKey) ([]byte, error) {
	return x509.WritePublicKeyToPem(key)
}

func WritePublicKeyToPemFile(filePath string, key *sm2.PublicKey) ([]byte, error) {
	publicKeyPem, err := x509.WritePublicKeyToPem(key)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(filePath, publicKeyPem, 0644)
	if err != nil {
		return nil, err
	}
	return publicKeyPem, nil
}

func ReadPrivateKeyFromHex(Dhex string) (*sm2.PrivateKey, error) {
	return x509.ReadPrivateKeyFromHex(Dhex)
}

func WritePrivateKeyToHex(key *sm2.PrivateKey) string {
	return x509.WritePrivateKeyToHex(key)
}

func ReadPublicKeyFromHex(Qhex string) (*sm2.PublicKey, error) {
	return x509.ReadPublicKeyFromHex(Qhex)
}

func WritePublicKeyToHex(key *sm2.PublicKey) string {
	return x509.WritePublicKeyToHex(key)
}

func ReadCertificateRequestFromPem(certPem []byte) (*x509.CertificateRequest, error) {
	return x509.ReadCertificateRequestFromPem(certPem)
}

func CreateCertificateRequestToPem(template *x509.CertificateRequest, signer crypto.Signer) ([]byte, error) {
	return x509.CreateCertificateRequestToPem(template, signer)
}

func ReadCertificateFromPem(certPem []byte) (*x509.Certificate, error) {
	return x509.ReadCertificateFromPem(certPem)
}

func CreateCertificate(template, parent *x509.Certificate, publicKey *sm2.PublicKey, signer crypto.Signer) ([]byte, error) {
	return x509.CreateCertificate(template, parent, publicKey, signer)
}

func CreateCertificateToPem(template, parent *x509.Certificate, pubKey *sm2.PublicKey, signer crypto.Signer) ([]byte, error) {
	return x509.CreateCertificateToPem(template, parent, pubKey, signer)
}
