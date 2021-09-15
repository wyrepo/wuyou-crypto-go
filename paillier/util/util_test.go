package util

import (
	"fmt"
	"github.com/wyrepo/wuyou-crypto-go/paillier/key"
	"github.com/wyrepo/wuyou-crypto-go/paillier/num"
	"io/ioutil"
	"math"
	"math/big"
	"testing"
)

func TestConverting(t *testing.T) {
	publicKey, privateKey, err := key.NewKeyPair(1024, math.MaxInt64)
	if err != nil {
		t.Error(err)
	}
	// add using original operands
	var eX, eY *num.Int
	x := big.NewInt(100000)
	y := big.NewInt(20)
	eX = num.NewInt(publicKey, x)
	eY = num.NewInt(publicKey, y)
	sum := new(num.Int).Add(eX, eY).Decrypt(privateKey)

	// Paillier.Int to Hex String (serialize)
	eXStr, err := IntToHexStr(eX)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("eX HexStr:%s\n", eXStr) // 1026 characters
	eYStr, err := IntToHexStr(eY)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("eY HexStr:%s\n", eYStr) // 1026 characters

	// Hex string to Paillier.Int (deserialize)
	eXNum, err := HexStrToInt(publicKey, eXStr)
	if err != nil {
		t.Error(err)
	}
	eYNum, err := HexStrToInt(publicKey, eYStr)
	if err != nil {
		t.Error(err)
	}

	// add using new operands
	sum2 := new(num.Int).Add(eXNum, eYNum).Decrypt(privateKey)
	fmt.Printf("sum:%v, sum2:%v\n", sum, sum2)
}

func TestKeyMarshalAndUnmarshal(t *testing.T) {
	publicKey, privateKey, err := key.NewKeyPair(1024, math.MaxInt64)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("pk.len:%v\n", publicKey.Length)           // 1024
	fmt.Printf("pk.N:%v\n", publicKey.N)                  // 617 characters
	fmt.Printf("pk.NSq:%v\n", publicKey.NSq)              // 1233 characters
	fmt.Printf("pk.G:%v\n", publicKey.G)                  // 617/618 characters
	fmt.Printf("sk.len:%v\n", privateKey.Length)          // 1024
	fmt.Printf("sk.L:%v\n", privateKey.L)                 // 617 characters
	fmt.Printf("sk.U:%v\n", privateKey.U)                 // 616 characters
	fmt.Printf("sk.Threshold:%v\n", privateKey.Threshold) // 9223372036854775807 // 19 characters

	// serialize public key
	bytes, err := MarshalPublicKey(publicKey)
	if err != nil {
		t.Error(err)
	}
	// deserialize public key
	pk, err := UnmarshalPublicKey(bytes)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("-pk.len:%v\n", pk.Length) // 1024
	fmt.Printf("-pk.N:%v\n", pk.N)        // 617 characters
	fmt.Printf("-pk.NSq:%v\n", pk.NSq)    // 1233 characters
	fmt.Printf("-pk.G:%v\n", pk.G)        // 617/618 characters

	// serialize private key
	bytes2, err := MarshalPrivateKey(privateKey)
	if err != nil {
		t.Error(err)
	}
	// deserialize private key
	sk, err := UnmarshalPrivateKey(bytes2)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("--pk.len:%v\n", sk.PublicKey.Length) // 1024
	fmt.Printf("--pk.N:%v\n", sk.PublicKey.N)        // 617 characters
	fmt.Printf("--pk.NSq:%v\n", sk.PublicKey.NSq)    // 1233 characters
	fmt.Printf("--pk.G:%v\n", sk.PublicKey.G)        // 617/618 characters
	fmt.Printf("-sk.len:%v\n", sk.Length)            // 1024
	fmt.Printf("-sk.L:%v\n", sk.L)                   // 617 characters
	fmt.Printf("-sk.U:%v\n", sk.U)                   // 616 characters
	fmt.Printf("-sk.Threshold:%v\n", sk.Threshold)   // 9223372036854775807 // 19 characters
}

func TestKeyWriteAndRead(t *testing.T) {
	publicKey, privateKey, err := key.NewKeyPair(1024, math.MaxInt64)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("pk.len:%v\n", publicKey.Length)           // 1024
	fmt.Printf("pk.N:%v\n", publicKey.N)                  // 617 characters
	fmt.Printf("pk.NSq:%v\n", publicKey.NSq)              // 1233 characters
	fmt.Printf("pk.G:%v\n", publicKey.G)                  // 617/618 characters
	fmt.Printf("sk.len:%v\n", privateKey.Length)          // 1024
	fmt.Printf("sk.L:%v\n", privateKey.L)                 // 617 characters
	fmt.Printf("sk.U:%v\n", privateKey.U)                 // 616 characters
	fmt.Printf("sk.Threshold:%v\n", privateKey.Threshold) // 9223372036854775807 // 19 characters

	// write public key to pem file
	pkPem, err := WritePublicKeyToPem(publicKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(string(pkPem))
	ioutil.WriteFile("publickey.key", pkPem, 0644)
	// read public key from pem file
	pkPem, err = ioutil.ReadFile("publickey.key")
	if err != nil {
		t.Error(err)
	}
	pk, err := ReadPublicKeyFromPem(pkPem)
	fmt.Printf("-pk.len:%v\n", pk.Length) // 1024
	fmt.Printf("-pk.N:%v\n", pk.N)        // 617 characters
	fmt.Printf("-pk.NSq:%v\n", pk.NSq)    // 1233 characters
	fmt.Printf("-pk.G:%v\n", pk.G)        // 617/618 characters

	// write private key to pem file
	skPem, err := WritePrivateKeyToPem(privateKey)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(string(skPem))
	ioutil.WriteFile("privatekey.key", skPem, 0644)
	// read private key from pem file
	skPem, err = ioutil.ReadFile("privatekey.key")
	if err != nil {
		t.Error(err)
	}
	sk, err := ReadPrivateKeyFromPem(skPem)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("--pk.len:%v\n", sk.PublicKey.Length) // 1024
	fmt.Printf("--pk.N:%v\n", sk.PublicKey.N)        // 617 characters
	fmt.Printf("--pk.NSq:%v\n", sk.PublicKey.NSq)    // 1233 characters
	fmt.Printf("--pk.G:%v\n", sk.PublicKey.G)        // 617/618 characters
	fmt.Printf("-sk.len:%v\n", sk.Length)            // 1024
	fmt.Printf("-sk.L:%v\n", sk.L)                   // 617 characters
	fmt.Printf("-sk.U:%v\n", sk.U)                   // 616 characters
	fmt.Printf("-sk.Threshold:%v\n", sk.Threshold)   // 9223372036854775807 // 19 characters
}
