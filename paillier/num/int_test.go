package num

import (
	"fmt"
	"github.com/wyrepo/wuyou-crypto-go/paillier/key"
	"math"
	"math/big"
	"testing"
)

func TestAdd(t *testing.T) {
	publicKey, privateKey := getKeyPair(t)
	var eX, eY *Int
	var testOperands operands
	for _, testOperands = range getTestOperands() {
		eX = NewInt(publicKey, testOperands.x)
		eY = NewInt(publicKey, testOperands.y)
		sum := new(Int).Add(eX, eY).Decrypt(privateKey)
		//require.Equal(t, testOperands.x.Add(testOperands.x, testOperands.y), sum)
		fmt.Printf("add:%v\n", sum)
	}

	//publicKey2, _ := getKeyPair(t)
	//eY = NewInt(publicKey2, testOperands.y)
	//require.Panics(t, func() { new(Int).Add(eX, eY) })
	//require.Panics(t, func() { new(Int).Add(eX, eY) })
}

func TestSub(t *testing.T) {
	publicKey, privateKey := getKeyPair(t)
	var eX, eY *Int
	var testOperands operands
	for _, testOperands = range getTestOperands() {
		eX = NewInt(publicKey, testOperands.x)
		eY = NewInt(publicKey, testOperands.y)
		diff := new(Int).Sub(eX, eY).Decrypt(privateKey)
		//require.Equal(t, testOperands.x.Sub(testOperands.x, testOperands.y), diff)
		fmt.Printf("sub:%v\n", diff)
	}

	//publicKey2, _ := getKeyPair(t)
	//eY = NewInt(publicKey2, testOperands.y)
	//require.Panics(t, func() { new(Int).Sub(eX, eY) })
	//require.Panics(t, func() { new(Int).Sub(eX, eY) })
}

func TestAddPlaintext(t *testing.T) {
	publicKey, privateKey := getKeyPair(t)
	for _, testOperands := range getTestOperands() {
		eX := NewInt(publicKey, testOperands.x)
		sum := new(Int).AddPlaintext(eX, testOperands.y).Decrypt(privateKey)
		//require.Equal(t, testOperands.x.Add(testOperands.x, testOperands.y), sum)
		fmt.Printf("add:%v\n", sum)
	}
}

func TestMulPlaintext(t *testing.T) {
	publicKey, privateKey := getKeyPair(t)
	for _, testOperands := range getTestOperands() {
		eX := NewInt(publicKey, testOperands.x)
		prod := new(Int).MulPlaintext(eX, testOperands.y).Decrypt(privateKey)
		//require.Equal(t, testOperands.x.Mul(testOperands.x, testOperands.y), prod)
		fmt.Printf("mul:%v\n", prod)
	}
}

func TestDivPlaintext(t *testing.T) {
	publicKey, privateKey := getKeyPair(t)
	var eX *Int
	for _, testOperands := range getTestDivOperands() {
		eX = NewInt(publicKey, testOperands.x)
		quotient := new(Int).DivPlaintext(eX, testOperands.y).Decrypt(privateKey)
		//require.Equal(t, testOperands.x.Div(testOperands.x, testOperands.y), quotient)
		fmt.Printf("div:%v\n", quotient)
	}

	//require.Panics(t, func() { new(Int).DivPlaintext(eX, big.NewInt(0)) })
}

func getKeyPair(t *testing.T) (*key.PublicKey, *key.PrivateKey) {
	publicKey, privateKey, err := key.NewKeyPair(256, math.MaxInt64)
	//require.NoError(t, err)
	if err != nil {
		t.Error(err)
	}
	return publicKey, privateKey
}

type operands struct {
	x *big.Int
	y *big.Int
}

func getTestOperands() []operands {
	return []operands{
		{big.NewInt(100), big.NewInt(75)},
		{big.NewInt(20), big.NewInt(0)},
		{big.NewInt(20), big.NewInt(21)},
		{big.NewInt(75), big.NewInt(100)},
		{big.NewInt(-100), big.NewInt(75)},
		{big.NewInt(100), big.NewInt(-75)},
		{big.NewInt(-100), big.NewInt(-75)},
		{big.NewInt(-10000), big.NewInt(-75)},
	}
}

func getTestDivOperands() []operands {
	return []operands{
		{big.NewInt(4), big.NewInt(2)},
		{big.NewInt(100), big.NewInt(25)},
		{big.NewInt(9), big.NewInt(3)},
		{big.NewInt(-9), big.NewInt(3)},
		{big.NewInt(9), big.NewInt(-3)},
		{big.NewInt(-9), big.NewInt(-3)},
		{big.NewInt(15), big.NewInt(1)},
	}
}
