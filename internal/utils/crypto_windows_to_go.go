package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"math/big"
)

func PublicKeyFromCNGECBlob(blob []byte) (crypto.PublicKey, error) {
	if len(blob) < 8 {
		return nil, errors.New("blob too short")
	}

	dwMagic := binary.LittleEndian.Uint32(blob[0:4])
	cbKey := int(binary.LittleEndian.Uint32(blob[4:8]))

	if len(blob) != 8+2*cbKey {
		return nil, errors.New("invalid blob length")
	}

	var curve elliptic.Curve
	switch dwMagic {
	case 0x31534345: // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
		curve = elliptic.P256()
	case 0x33534345: // BCRYPT_ECDSA_PUBLIC_P384_MAGIC
		curve = elliptic.P384()
	case 0x35534345: // BCRYPT_ECDSA_PUBLIC_P521_MAGIC
		curve = elliptic.P521()
	default:
		return nil, errors.New("unsupported ECC magic")
	}

	qxBytes := blob[8 : 8+cbKey]
	qyBytes := blob[8+cbKey : 8+2*cbKey]

	x := new(big.Int).SetBytes(qxBytes)
	y := new(big.Int).SetBytes(qyBytes)

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid point on curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
