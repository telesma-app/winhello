//go:build windows

package winhello

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"uuid"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
)

var clsid = "{1537ff70-8f94-495b-bad1-bcff96311d5f}"

func requirePluginTest(t *testing.T) {
	t.Helper()

	if enabled := os.Getenv("WINHELLO_PLUGIN_TESTS"); enabled != "1" && enabled != "true" {
		t.Skip("WINHELLO_PLUGIN_TESTS is not set")
	}
}

func TestAddAuthenticator(t *testing.T) {
	requirePluginTest(t)

	state, err := PluginGetAuthenticatorState(clsid)
	if err != nil {
		t.Fatal(err)
	}

	if state != PluginAuthenticatorStateEnabled {
		t.Fatal("Authenticator is not enabled")
	}

	_, err = PluginAddAuthenticator(&PluginAddAuthenticatorOptions{
		AuthenticatorName: "WinHello Passkey Demo",
		CLSID:             clsid,
		PluginRPID:        "id.krasovs.ky",
		//DarkThemeLogoSvg:  svg,
		AuthenticatorInfo: &protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{"FIDO_2_1", "FIDO_2_0"},
			Extensions:         []extension.ExtensionIdentifier{"prf", extension.ExtensionIdentifierHMACSecret},
			AAGUID:             uuid.MustParse("fd34cf01-7dab-462e-92f9-f66be96e599c"),
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo, protocol.PinUvAuthProtocolOne},
			Options: map[protocol.Option]bool{
				protocol.OptionResidentKeys:     true,
				protocol.OptionUserPresence:     true,
				protocol.OptionUserVerification: true,
				protocol.OptionAlwaysUv:         true,
			},
			Transports: []credential.AuthenticatorTransport{credential.AuthenticatorTransportInternal},
			Algorithms: []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}},
		},
	})
	assert.NoError(t, err)

	//PluginRemoveAuthenticator(clsid)
}

func TestPluginAuthenticatorCredentials(t *testing.T) {
	requirePluginTest(t)

	err := PluginAuthenticatorAddCredentials(clsid, []*PluginCredentialDetail{
		{
			CredentialID:    []byte("1234567890"),
			RPID:            "id.krasovs.ky",
			RPName:          "WinHello Passkey Demo",
			UserID:          []byte("savely"),
			UserName:        "savely",
			UserDisplayName: "Savely",
		},
	})
	assert.NoError(t, err)

	credentials, err := PluginAuthenticatorGetAllCredentials(clsid)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, credentials)

	assert.Equal(t, "1234567890", string(credentials[0].CredentialID))

	err = PluginAuthenticatorRemoveCredentials(clsid, []*PluginCredentialDetail{
		{CredentialID: []byte("1234567890")},
	})
	assert.NoError(t, err)

	err = PluginAuthenticatorAddCredentials(clsid, []*PluginCredentialDetail{
		{
			CredentialID:    []byte("1234567890"),
			RPID:            "id.krasovs.ky",
			RPName:          "WinHello Passkey Demo",
			UserID:          []byte("savely"),
			UserName:        "savely",
			UserDisplayName: "Savely",
		},
	})
	assert.NoError(t, err)

	credentials, err = PluginAuthenticatorGetAllCredentials(clsid)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, credentials)

	assert.Equal(t, "1234567890", string(credentials[0].CredentialID))

	err = PluginAuthenticatorRemoveAllCredentials(clsid)
	assert.NoError(t, err)
}

func TestPluginPerformUserVerification(t *testing.T) {
	requirePluginTest(t)

	_, err := PluginPerformUserVerification(&PluginUserVerificationRequestOptions{
		WindowHandle:  0,
		TransactionID: clsid,
		Username:      "",
		DisplayHint:   "",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPluginGetUserVerificationCount(t *testing.T) {
	requirePluginTest(t)

	count, err := PluginGetUserVerificationCount(clsid)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, count, uint32(0))
}

func TestPluginGetUserVerificationPublicKey(t *testing.T) {
	requirePluginTest(t)

	pubKey, err := PluginGetUserVerificationPublicKey(clsid)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, pubKey)
}

func TestPluginGetOperationSigningPublicKey(t *testing.T) {
	requirePluginTest(t)

	pubKey, err := PluginGetOperationSigningPublicKey(clsid)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, pubKey)
}

func TestPluginEncodeMakeCredentialResponse(t *testing.T) {
	requirePluginTest(t)

	b, err := hex.DecodeString("13d2cbaa54c70765984a2c06e961c05dbebc030509adb7f9b24fe39518885faa45000033b3eabb46cce24180bfae9e96fa6d2975cf006008172df33bb4e0a992eb2294d5f7d022f475f4429c4c2945707c9c0de078ea201a0fb90f30be44d93c808267f3b506fbcafb76293ce7fcb47c2488bfe1d0fc214734811d5e6a0bc901766f953e8e70ae1ae3ae647c88a4f3fe2cdd801b71d48ea50102032620012158206d21de7d8f97ea995b9163b190150c20b4f9b98ab622893cffbf896b217eba392258208e260991d7cdbf6f6dbb36dc718fab30bdfaa9aff33c30b5068f1822e33bf75e")
	if err != nil {
		t.Fatal(err)
	}

	encodedResponse, err := PluginEncodeMakeCredentialResponse(&WinHelloMakeCredentialResponse{
		AuthenticatorMakeCredentialResponse: &protocol.AuthenticatorMakeCredentialResponse{
			Format:               attestation.AttestationStatementFormatIdentifierNone,
			AuthDataRaw:          b,
			AttestationStatement: map[string]any{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var response protocol.AuthenticatorMakeCredentialResponse
	if err := cbor.Unmarshal(encodedResponse, &response); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, attestation.AttestationStatementFormatIdentifierNone, response.Format)
	assert.Equal(t, b, response.AuthDataRaw)
	assert.Equal(t, map[string]any{}, response.AttestationStatement)
}

func TestPluginEncodeGetAssertionResponse(t *testing.T) {
	requirePluginTest(t)

	rpIDHash := sha256.Sum256([]byte("example.com"))
	authData := append(rpIDHash[:], 0x05, 0, 0, 0, 0)
	signature := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	descriptor := credential.PublicKeyCredentialDescriptor{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   []byte("test credential"),
	}
	user := &credential.PublicKeyCredentialUserEntity{ID: []byte("test user")}

	encodedResponse, err := PluginEncodeGetAssertionResponse(&CTAPCBORGetAssertionResponse{
		WinHelloGetAssertionResponse: &WinHelloGetAssertionResponse{
			AuthenticatorGetAssertionResponse: &protocol.AuthenticatorGetAssertionResponse{
				Credential:  descriptor,
				AuthDataRaw: authData,
				Signature:   signature,
				User:        user,
			},
		},
		UserInformation:     user,
		NumberOfCredentials: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	var response protocol.AuthenticatorGetAssertionResponse
	if err := cbor.Unmarshal(encodedResponse, &response); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, descriptor, response.Credential)
	assert.Equal(t, authData, response.AuthDataRaw)
	assert.Equal(t, signature, response.Signature)
	assert.Equal(t, user, response.User)
	// The count may be omitted for a single credential.
	assert.LessOrEqual(t, response.NumberOfCredentials, uint(1))
}
