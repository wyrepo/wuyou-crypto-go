package key

import "math/big"

// PublicKeyInfo is used to serialize
type PublicKeyInfo struct {
	Length int
	N      *big.Int
}

// PrivateKeyInfo is used to serialize
type PrivateKeyInfo struct {
	Length    int
	L         *big.Int
	N         *big.Int
	Threshold *big.Int
}
