package demoauthenticator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sync"
	"uuid"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
)

// AAGUID identifies the demo authenticator in GetInfo and registration data.
const AAGUID = "fd34cf01-7dab-462e-92f9-f66be96e599c"

const (
	credentialIDSize = 32
	maxUserIDSize    = 64
	authDataSize     = sha256.Size + 1 + 4
	verifiedFlags    = protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified
)

var (
	ErrInvalidRequest       = errors.New("invalid authenticator request")
	ErrUnsupportedAlgorithm = errors.New("ES256 was not offered")
	ErrUnsupportedOption    = errors.New("the demo only creates discoverable credentials")
	ErrCredentialExcluded   = errors.New("credential excluded")
	ErrCredentialStoreFull  = errors.New("the demo already stores one credential")
	ErrNoCredentials        = errors.New("no matching credential")
)

// Authenticator creates and uses one local ES256 credential. The caller must
// verify user presence and identity before each operation.
type Authenticator struct {
	path      string
	protect   func([]byte) ([]byte, error)
	unprotect func([]byte) ([]byte, error)
	mu        sync.Mutex
}

func (a *Authenticator) MakeCredential(req *protocol.AuthenticatorMakeCredentialRequest) (*protocol.AuthenticatorMakeCredentialResponse, error) {
	if req.RP.ID == "" || len(req.ClientDataHash) != sha256.Size || len(req.User.ID) == 0 || len(req.User.ID) > maxUserIDSize {
		return nil, ErrInvalidRequest
	}

	if !slices.Contains(req.PubKeyCredParams, credential.PublicKeyCredentialParameters{
		Type:      credential.PublicKeyCredentialTypePublicKey,
		Algorithm: cose.AlgorithmES256,
	}) {
		return nil, ErrUnsupportedAlgorithm
	}

	if !req.Options[protocol.OptionResidentKeys] {
		return nil, ErrUnsupportedOption
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	stored, err := a.readCredential()
	switch {
	case err == nil:
		clear(stored.PrivateKey)

		if stored.RPID == req.RP.ID && containsCredential(req.ExcludeList, stored.ID) {
			return nil, ErrCredentialExcluded
		}

		return nil, ErrCredentialStoreFull
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate credential key: %w", err)
	}

	privateKey, err := key.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode credential key: %w", err)
	}
	defer clear(privateKey)

	id := make([]byte, credentialIDSize)
	_, _ = rand.Read(id)

	const coordinateSize = 32

	point, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode credential point: %w", err)
	}

	publicKey := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   point[1 : 1+coordinateSize : 1+coordinateSize],
		cose.EC2KeyParameterY:   point[1+coordinateSize:],
	}
	enc, _ := cbor.CTAP2EncOptions().EncMode()

	encodedKey, err := enc.Marshal(publicKey)
	if err != nil {
		return nil, fmt.Errorf("encode credential public key: %w", err)
	}

	attested := &protocol.AttestedCredentialData{
		AAGUID:              uuid.MustParse(AAGUID),
		CredentialID:        id,
		CredentialPublicKey: publicKey,
	}
	rpHash := sha256.Sum256([]byte(req.RP.ID))
	flags := verifiedFlags | protocol.AuthDataFlagAttestedCredentialDataIncluded
	authData := appendAuthData(make([]byte, 0, authDataSize+len(attested.AAGUID)+2+len(id)+len(encodedKey)), rpHash, flags)
	authData = append(authData, attested.AAGUID[:]...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(id)))
	authData = append(authData, id...)
	authData = append(authData, encodedKey...)

	if err := a.writeCredential(storedCredential{ID: id, RPID: req.RP.ID, User: req.User, PrivateKey: privateKey}); err != nil {
		return nil, err
	}

	return &protocol.AuthenticatorMakeCredentialResponse{
		Format:               attestation.AttestationStatementFormatIdentifierNone,
		AuthDataRaw:          authData,
		AttestationStatement: map[string]any{},
		AuthData: &protocol.MakeCredentialAuthData{
			RPIDHash:               rpHash[:],
			Flags:                  flags,
			AttestedCredentialData: attested,
		},
	}, nil
}

func (a *Authenticator) GetAssertion(req *protocol.AuthenticatorGetAssertionRequest) (*protocol.AuthenticatorGetAssertionResponse, error) {
	if req.RPID == "" || len(req.ClientDataHash) != sha256.Size {
		return nil, ErrInvalidRequest
	}

	stored, err := a.readCredential()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoCredentials
	}

	if err != nil {
		return nil, err
	}

	defer clear(stored.PrivateKey)

	if req.RPID != stored.RPID || (len(req.AllowList) != 0 && !containsCredential(req.AllowList, stored.ID)) {
		return nil, ErrNoCredentials
	}

	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), stored.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode credential key: %w", err)
	}

	rpHash := sha256.Sum256([]byte(req.RPID))
	authData := appendAuthData(make([]byte, 0, authDataSize+sha256.Size), rpHash, verifiedFlags)
	// The signed message is authenticatorData || clientDataHash.
	digest := sha256.Sum256(append(authData, req.ClientDataHash...))

	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign assertion: %w", err)
	}

	return &protocol.AuthenticatorGetAssertionResponse{
		Credential: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   stored.ID,
		},
		AuthDataRaw: authData[:len(authData):len(authData)],
		AuthData: &protocol.GetAssertionAuthData{
			RPIDHash: rpHash[:],
			Flags:    verifiedFlags,
		},
		Signature: signature,
		User:      &stored.User,
	}, nil
}

func appendAuthData(dst []byte, rpHash [sha256.Size]byte, flags protocol.AuthDataFlag) []byte {
	dst = append(dst, rpHash[:]...)
	dst = append(dst, byte(flags))
	// An authenticator without a signature counter leaves signCount at zero.
	return binary.BigEndian.AppendUint32(dst, 0)
}

func containsCredential(list []credential.PublicKeyCredentialDescriptor, id []byte) bool {
	return slices.ContainsFunc(list, func(candidate credential.PublicKeyCredentialDescriptor) bool {
		return candidate.Type == credential.PublicKeyCredentialTypePublicKey && bytes.Equal(candidate.ID, id)
	})
}
