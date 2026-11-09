package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
)

func PublicKeyFromCNGBlob(blob []byte) (crypto.PublicKey, error) {
	if len(blob) < 4 {
		return nil, errors.New("truncated CNG public key")
	}

	switch binary.LittleEndian.Uint32(blob) {
	case 0x31534345: // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
		return parseCNGECKey(blob, elliptic.P256())
	case 0x33534345: // BCRYPT_ECDSA_PUBLIC_P384_MAGIC
		return parseCNGECKey(blob, elliptic.P384())
	case 0x35534345: // BCRYPT_ECDSA_PUBLIC_P521_MAGIC
		return parseCNGECKey(blob, elliptic.P521())
	case 0x31415352: // BCRYPT_RSAPUBLIC_MAGIC
		return parseCNGRSAKey(blob)
	default:
		return nil, errors.New("unsupported CNG public key format")
	}
}

func parseCNGECKey(blob []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	const headerSize = 8

	size := (curve.Params().BitSize + 7) / 8
	if len(blob) != headerSize+2*size || binary.LittleEndian.Uint32(blob[4:]) != uint32(size) {
		return nil, errors.New("invalid CNG ECDSA public key length")
	}

	return ecdsa.ParseUncompressedPublicKey(curve, append([]byte{4}, blob[headerSize:]...))
}

func parseCNGRSAKey(blob []byte) (*rsa.PublicKey, error) {
	const headerSize = 24
	if len(blob) < headerSize {
		return nil, errors.New("truncated CNG RSA public key")
	}

	bitLength := binary.LittleEndian.Uint32(blob[4:8])
	exponentSize := binary.LittleEndian.Uint32(blob[8:12])

	modulusSize := binary.LittleEndian.Uint32(blob[12:16])
	if uint64(exponentSize)+uint64(modulusSize) != uint64(len(blob)-headerSize) ||
		binary.LittleEndian.Uint32(blob[16:20]) != 0 || binary.LittleEndian.Uint32(blob[20:24]) != 0 {
		return nil, errors.New("invalid CNG RSA public key length")
	}

	// BCRYPT_RSAKEY_BLOB encodes the exponent and modulus in big-endian order.
	payload := blob[headerSize:]
	exponent := new(big.Int).SetBytes(payload[:exponentSize])

	modulus := new(big.Int).SetBytes(payload[exponentSize:])
	if !exponent.IsUint64() || exponent.Uint64() < 3 || exponent.Uint64() > math.MaxInt32 || exponent.Bit(0) == 0 ||
		uint64(modulus.BitLen()) != uint64(bitLength) || modulus.Bit(0) == 0 {
		return nil, errors.New("invalid CNG RSA public key")
	}

	return &rsa.PublicKey{N: modulus, E: int(exponent.Uint64())}, nil
}

// VerifyCNGSignature verifies the signature format used by Windows for plugin
// operation requests and user verification responses.
func VerifyCNGSignature(key crypto.PublicKey, message, signature []byte) error {
	digest := sha256.Sum256(message)

	switch key := key.(type) {
	case *ecdsa.PublicKey:
		size := (key.Params().N.BitLen() + 7) / 8
		if len(signature) != 2*size {
			return errors.New("invalid CNG ECDSA signature length")
		}

		r := new(big.Int).SetBytes(signature[:size])

		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(key, digest[:], r, s) {
			return errors.New("invalid CNG ECDSA signature")
		}

		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: sha256.Size})
	default:
		return errors.New("unsupported CNG signature key")
	}
}
