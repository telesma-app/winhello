package demoauthenticator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
)

func TestCredentialSurvivesRestart(t *testing.T) {
	const rpID = "example.test"

	userID := []byte{1, 2, 3}

	if path := os.Getenv("WINHELLO_DEMO_TEST_STORE"); path != "" {
		a := testAuthenticator(path)
		hash := sha256.Sum256([]byte("second browser challenge"))
		req := &protocol.AuthenticatorGetAssertionRequest{RPID: rpID, ClientDataHash: hash[:]}

		assertion, err := a.GetAssertion(req)
		if err != nil {
			t.Fatal(err)
		}

		if got := hex.EncodeToString(assertion.Credential.ID); got != os.Getenv("WINHELLO_DEMO_TEST_CREDENTIAL_ID") {
			t.Fatalf("credential ID after restart = %s", got)
		}

		if assertion.User == nil || !bytes.Equal(assertion.User.ID, userID) {
			t.Fatal("assertion returned the wrong user")
		}

		rpHash := sha256.Sum256([]byte(rpID))

		want := append(rpHash[:], 0x05, 0, 0, 0, 0)
		if !bytes.Equal(assertion.AuthDataRaw, want) {
			t.Fatalf("assertion authenticator data = %x, want %x", assertion.AuthDataRaw, want)
		}

		keyBytes, err := hex.DecodeString(os.Getenv("WINHELLO_DEMO_TEST_PUBLIC_KEY"))
		if err != nil {
			t.Fatal(err)
		}

		key, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			t.Fatal(err)
		}

		digest := sha256.Sum256(append(want, hash[:]...))
		if !ecdsa.VerifyASN1(key.(*ecdsa.PublicKey), digest[:], assertion.Signature) {
			t.Fatal("assertion signature did not verify against the registered credential")
		}

		req.AllowList = []credential.PublicKeyCredentialDescriptor{{Type: credential.PublicKeyCredentialTypePublicKey, ID: []byte{4, 5, 6}}}
		if _, err := a.GetAssertion(req); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("nonmatching allow list error = %v", err)
		}

		req.AllowList = nil

		req.RPID = "other.test"
		if _, err := a.GetAssertion(req); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("wrong RP error = %v", err)
		}

		return
	}

	path := filepath.Join(t.TempDir(), "credential.dat")
	a := testAuthenticator(path)
	req := testMakeCredentialRequest(rpID, userID)

	created, err := a.MakeCredential(req)
	if err != nil {
		t.Fatal(err)
	}

	if created.Format != attestation.AttestationStatementFormatIdentifierNone || created.AttestationStatement == nil || len(created.AttestationStatement) != 0 {
		t.Fatal("registration did not return an empty none attestation statement")
	}

	parsed, err := protocol.ParseMakeCredentialAuthData(created.AuthDataRaw)
	if err != nil {
		t.Fatal(err)
	}

	rpHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(parsed.RPIDHash, rpHash[:]) || parsed.Flags != 0x45 || parsed.SignCount != 0 {
		t.Fatalf("registration authenticator data header = %x", created.AuthDataRaw[:37])
	}

	attested := parsed.AttestedCredentialData
	if attested == nil || attested.AAGUID != uuid.MustParse(AAGUID) || len(attested.CredentialID) != 32 {
		t.Fatal("registration did not return the demo's attested credential")
	}

	algorithm, err := attested.CredentialPublicKey.Algorithm()
	if err != nil || algorithm != cose.AlgorithmES256 {
		t.Fatalf("registered credential algorithm = %v, %v", algorithm, err)
	}

	publicKey, err := attested.CredentialPublicKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.MakeCredential(req); !errors.Is(err, ErrCredentialStoreFull) {
		t.Errorf("second credential creation error = %v", err)
	}

	req.ExcludeList = []credential.PublicKeyCredentialDescriptor{{Type: credential.PublicKeyCredentialTypePublicKey, ID: attested.CredentialID}}
	if _, err := a.MakeCredential(req); !errors.Is(err, ErrCredentialExcluded) {
		t.Errorf("excluded credential creation error = %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialSurvivesRestart$")

	cmd.Env = append(os.Environ(),
		"WINHELLO_DEMO_TEST_STORE="+path,
		"WINHELLO_DEMO_TEST_CREDENTIAL_ID="+hex.EncodeToString(attested.CredentialID),
		"WINHELLO_DEMO_TEST_PUBLIC_KEY="+hex.EncodeToString(publicKeyBytes),
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify credential after provider restart: %v\n%s", err, output)
	}
}

func TestRemoveCredentialRollsBackMatchingID(t *testing.T) {
	a := testAuthenticator(filepath.Join(t.TempDir(), "credential.dat"))
	req := testMakeCredentialRequest("example.test", []byte{1, 2, 3})

	created, err := a.MakeCredential(req)
	if err != nil {
		t.Fatal(err)
	}

	id := created.AuthData.AttestedCredentialData.CredentialID

	if err := a.RemoveCredential([]byte{4, 5, 6}); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("remove different credential error = %v", err)
	}

	if err := a.RemoveCredential(id); err != nil {
		t.Fatal(err)
	}

	retried, err := a.MakeCredential(req)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(id, retried.AuthData.AttestedCredentialData.CredentialID) {
		t.Fatal("retry reused the rolled back credential")
	}
}

func testMakeCredentialRequest(rpID string, userID []byte) *protocol.AuthenticatorMakeCredentialRequest {
	hash := sha256.Sum256([]byte("first browser challenge"))

	return &protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash: hash[:],
		RP:             credential.PublicKeyCredentialRpEntity{ID: rpID},
		User:           credential.PublicKeyCredentialUserEntity{ID: userID},
		PubKeyCredParams: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		Options: map[protocol.Option]bool{protocol.OptionResidentKeys: true},
	}
}
