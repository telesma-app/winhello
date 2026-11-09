package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestVerifyCNGSignatureECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const coordinateSize = 32

	blob := make([]byte, 8+2*coordinateSize)
	copy(blob, "ECS1")
	binary.LittleEndian.PutUint32(blob[4:], coordinateSize)
	privateKey.X.FillBytes(blob[8 : 8+coordinateSize])
	privateKey.Y.FillBytes(blob[8+coordinateSize:])

	key, err := PublicKeyFromCNGBlob(blob)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("original request")
	digest := sha256.Sum256(message)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	signature := make([]byte, 2*coordinateSize)
	r.FillBytes(signature[:coordinateSize])
	s.FillBytes(signature[coordinateSize:])

	if err := VerifyCNGSignature(key, message, signature); err != nil {
		t.Fatal(err)
	}

	if err := VerifyCNGSignature(key, []byte("different request"), signature); err == nil {
		t.Fatal("signature accepted for different request bytes")
	}

	if err := VerifyCNGSignature(key, message, signature[1:]); err == nil {
		t.Fatal("truncated signature accepted")
	}
}

func TestVerifyCNGSignatureRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	exponent := big.NewInt(int64(privateKey.E)).Bytes()
	modulus := privateKey.N.Bytes()
	blob := make([]byte, 24, 24+len(exponent)+len(modulus))
	copy(blob, "RSA1")
	binary.LittleEndian.PutUint32(blob[4:], uint32(privateKey.N.BitLen()))
	binary.LittleEndian.PutUint32(blob[8:], uint32(len(exponent)))
	binary.LittleEndian.PutUint32(blob[12:], uint32(len(modulus)))
	blob = append(blob, exponent...)
	blob = append(blob, modulus...)

	key, err := PublicKeyFromCNGBlob(blob)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := PublicKeyFromCNGBlob(blob[:len(blob)-1]); err == nil {
		t.Fatal("truncated RSA blob accepted")
	}

	message := []byte("original request")
	digest := sha256.Sum256(message)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: sha256.Size})
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyCNGSignature(key, message, signature); err != nil {
		t.Fatal(err)
	}

	if err := VerifyCNGSignature(key, []byte("different request"), signature); err == nil {
		t.Fatal("signature accepted for different request bytes")
	}
}
