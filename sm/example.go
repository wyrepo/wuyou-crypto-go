package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm2"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm3"
	"github.com/wyrepo/wuyou-crypto-go/sm/sm4"
	"github.com/wyrepo/wuyou-crypto-go/sm/util"
	"github.com/wyrepo/wuyou-crypto-go/sm/x509"

	"log"
)

func main() {
	// examples for sm2
	sm2KeysOperations()
	sm2EncryptAndDecrypt()
	sm2SignAndVerify()

	// examples for sm3
	sm3Digest()

	// examples for sm4
	sm4KeysOperations()
	sm4EncryptAndDecrypt()
}

func sm2KeysOperations() {
	// generate two keys
	privateKay, err := sm2.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, _ := privateKay.Public().(*sm2.PublicKey)
	fmt.Println(util.WritePrivateKeyToHex(privateKay)) // delete this line in project
	fmt.Println(util.WritePublicKeyToHex(publicKey))   // delete this line in project

	// write key to pem (pem can be used to serialize)
	privateKeyPem, err := util.WritePrivateKeyToPem(privateKay, nil)
	if err != nil {
		log.Fatalf("Write private key to pem error:%v\n", err)
	}
	publicKeyPem, err := util.WritePublicKeyToPem(publicKey)
	if err != nil {
		log.Fatalf("Write public key to pem error:%v\n", err)
	}
	fmt.Printf("Private key pem:%02x\n", privateKeyPem) // delete this line in project
	fmt.Printf("Public key pem:%02x\n", publicKeyPem)   // delete this line in project

	// read key from pem (deserialize from pem)
	privateKay, err = util.ReadPrivateKeyFromPem(privateKeyPem, nil)
	if err != nil {
		log.Fatalf("Read private key from pem error:%v\n", err)
	}
	publicKey, err = util.ReadPublicKeyFromPem(publicKeyPem)
	if err != nil {
		log.Fatalf("Read public key from pem error:%v\n", err)
	}

	// check certificate's signature
	templateReq := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "tjfoc.gmsm.com",
			Organization: []string{"tjfoc"},
		},
		SignatureAlgorithm: x509.SM2WithSM3,
	}
	certReqPem, err := util.CreateCertificateRequestToPem(&templateReq, privateKay)
	if err != nil {
		log.Fatalf("Create certificate request to pem error:%v\n", err)
	}
	certReq, err := util.ReadCertificateRequestFromPem(certReqPem)
	if err != nil {
		log.Fatalf("Read certicate request from pem error:%v\n", err)
	}
	err = certReq.CheckSignature()
	if err != nil {
		log.Fatalf("Check certificate's signature error:%v", err)
	} else {
		fmt.Printf("Check certificate's signature ok\n")
	}
}

func sm2EncryptAndDecrypt() {
	// generate two keys
	privateKay, err := sm2.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, _ := privateKay.Public().(*sm2.PublicKey)

	// encrypt and decrypt (1st WAY)
	msg := []byte("123456")
	msgEncrypted, err := publicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		log.Fatalf("SM2 Encrypt error:%v\n", err)
	}
	fmt.Printf("msgEncrypted:%02x\n", msgEncrypted)
	msgDecrypted, err := privateKay.DecryptAsn1(msgEncrypted)
	if err != nil {
		log.Fatalf("SM2 Decrypt error:%v\n", err)
	}
	fmt.Printf("msgDecrypted:%s\n", msgDecrypted)

	// encrypt and decrypt (2nd WAY)
	msgEncrypted2, err := sm2.EncryptAsn1(publicKey, msg, rand.Reader)
	if err != nil {
		log.Fatalf("SM2 Encrypt error:%v\n", err)
	}
	fmt.Printf("msgEncrypted2:%02x\n", msgEncrypted2)
	msgDecrypted2, err := sm2.DecryptAsn1(privateKay, msgEncrypted2)
	if err != nil {
		log.Fatalf("SM2 Decrypt error:%v\n", err)
	}
	fmt.Printf("msgDecrypted2:%s\n", msgDecrypted2)

	// encrypt and decrypt (3rd WAY)
	msgEncrypted3, err := sm2.Encrypt(publicKey, msg, rand.Reader, sm2.C1C2C3)
	if err != nil {
		log.Fatalf("SM2 Encrypt error:%v\n", err)
	}
	fmt.Printf("msgEncrypted3:%02x\n", msgEncrypted3)
	msgDecrypted3, err := sm2.Decrypt(privateKay, msgEncrypted3, sm2.C1C2C3)
	if err != nil {
		log.Fatalf("SM2 Decrypt error:%v\n", err)
	}
	fmt.Printf("msgDecrypted3:%s\n", msgDecrypted3)
}

func sm2SignAndVerify() {
	// generate two keys
	privateKay, err := sm2.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, _ := privateKay.Public().(*sm2.PublicKey)

	// sign
	msg := []byte("123456")
	sign, err := privateKay.Sign(rand.Reader, msg, nil)
	if err != nil {
		log.Fatalf("Sign using private key error:%v\n", err)
	}
	// verify
	ok := publicKey.Verify(msg, sign)
	if !ok {
		fmt.Printf("Verify using public key error\n")
	} else {
		fmt.Printf("Verify using public key ok\n")
	}
}

func sm3Digest() {
	msg := []byte("123456")
	hash := sm3.Sm3Sum(msg)
	hashHex := fmt.Sprintf("%02x", hash)
	fmt.Printf("digest:%s\n", hashHex)
}

func sm4KeysOperations() {
	key := []byte("1234567890abcdef")

	// write key to pem (pem can be used to serialize)
	keyToPem, err := sm4.WriteKeyToPem(key, nil)
	if err != nil {
		log.Fatalf("Write key to pem error:%v\n", err)
	}
	// read key from pem (deserialize from pem)
	keyPem, err := sm4.ReadKeyFromPem(keyToPem, nil)
	if err != nil {
		log.Fatalf("Read key from pem error:%v\n", err)
	}
	fmt.Printf("keyRaw:%v\nkeyPem:%v\n", key, keyPem) // delete this line in project

	// write key to pem file (pem file can be used to serialize)
	err = sm4.WriteKeyToPemFile("key.pem", key, nil)
	if err != nil {
		log.Fatalf("Write key to pem file error:%v\n", err)
	}
	// read key from pem file (deserialize from pem file)
	keyPem2, err := sm4.ReadKeyFromPemFile("key.pem", nil)
	if err != nil {
		log.Fatalf("Read key from pem file error:%v\n", err)
	}
	fmt.Printf("keyRaw:%v\nkeyPem:%v\n", key, keyPem2) // delete this line in project
}

func sm4EncryptAndDecrypt() {
	// SM4 key size must be 16
	key := []byte("1234567890abcdef")

	msg := []byte("123456")

	// encrypt, mode = true
	msgEncrypted, err := sm4.Sm4Cbc(key, msg, true)
	if err != nil {
		log.Fatalf("SM4 encrypt error:%v\n", err)
	}
	fmt.Printf("msgEncrypted:%02x\n", msgEncrypted)

	// decrypt, mode = false
	msgDecrypted, err := sm4.Sm4Cbc(key, msgEncrypted, false)
	if err != nil {
		log.Fatalf("SM4 decrypt error:%v\n", err)
	}
	fmt.Printf("msgDecrypted:%s\n", msgDecrypted)
}
