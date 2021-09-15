package util

import (
	"crypto"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm2"
	"github.com/wyrepo/wuyou-crypto-go/sm/x509"
)

func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (*sm2.PrivateKey, error) {
	return x509.ReadPrivateKeyFromPem(privateKeyPem, pwd)
}

func WritePrivateKeyToPem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	return x509.WritePrivateKeyToPem(key, pwd)
}

func ReadPublicKeyFromPem(publicKeyPem []byte) (*sm2.PublicKey, error) {
	return x509.ReadPublicKeyFromPem(publicKeyPem)
}

func WritePublicKeyToPem(key *sm2.PublicKey) ([]byte, error) {
	return x509.WritePublicKeyToPem(key)
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
