//go:build windows

package winhello

import (
	"encoding/base64"
	"log/slog"
	"os"
	"testing"

	"github.com/go-ctap/winhello/hiddenwindow"
	"github.com/goforj/godump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/webauthn"
	"golang.org/x/sys/windows"
)

var (
	hWnd windows.HWND
)

func runWinHelloTests() bool {
	env := os.Getenv("WINHELLO_TESTS")
	return env == "true" || env == "1"
}

func TestMain(m *testing.M) {
	if !runWinHelloTests() {
		m.Run()
	} else {
		wnd, err := hiddenwindow.New(slog.New(slog.DiscardHandler), "WebAuthn Tests")
		if err != nil {
			panic(err)
		}
		defer wnd.Close()

		hWnd = wnd.WindowHandle()

		m.Run()
	}
}

func TestAuthenticatorMakePlatformCredential(t *testing.T) {
	if !runWinHelloTests() {
		t.Skip("Skipping test because WINHELLO_TESTS is not set")
	}

	credAttestation, err := MakeCredential(
		hWnd,
		[]byte("{}"),
		credential.PublicKeyCredentialRpEntity{
			ID:   "example.org",
			Name: "Example RP",
		},
		credential.PublicKeyCredentialUserEntity{
			ID:          []byte("john"),
			Name:        "John Doe",
			DisplayName: "John Doe",
		},
		[]credential.PublicKeyCredentialParameters{
			{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			},
		},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialPropertiesInputs: &webauthn.CreateCredentialPropertiesInputs{
				CredentialProperties: true,
			},
		},
		&AuthenticatorMakeCredentialOptions{
			AuthenticatorAttachment:         WinHelloAuthenticatorAttachmentPlatform,
			AttestationConveyancePreference: WinHelloAttestationConveyancePreferenceDirect,
			RequireResidentKey:              true,
		},
	)
	require.NoError(t, err)

	// credProps
	assert.Equal(t, new(true), credAttestation.ExtensionOutputs.CredentialProperties.ResidentKey)

	godump.Dump(credAttestation)
}

func TestGetPlatformAssertion(t *testing.T) {
	if !runWinHelloTests() {
		t.Skip("Skipping test because WINHELLO_TESTS is not set")
	}

	assertion, err := GetAssertion(
		hWnd,
		"example.org",
		[]byte("{}"),
		nil,
		nil,
		&AuthenticatorGetAssertionOptions{
			AuthenticatorAttachment:     WinHelloAuthenticatorAttachmentPlatform,
			UserVerificationRequirement: WinHelloUserVerificationRequirementDiscouraged,
			CredentialHints: []credential.PublicKeyCredentialHint{
				credential.PublicKeyCredentialHintClientDevice,
				credential.PublicKeyCredentialHintSecurityKey,
				credential.PublicKeyCredentialHintHybrid,
			},
		},
	)
	require.NoError(t, err)

	godump.Dump(assertion)
}

func TestPlatformCredentialList(t *testing.T) {
	if !runWinHelloTests() {
		t.Skip("Skipping test because WINHELLO_TESTS is not set")
	}

	list, err := PlatformCredentialList("", false)
	require.NoError(t, err)
	require.NotEmpty(t, list)

	for _, cred := range list {
		godump.Dump(cred)
	}
}

func TestDeletePlatformCredential(t *testing.T) {
	if !runWinHelloTests() {
		t.Skip("Skipping test because WINHELLO_TESTS is not set")
	}

	list, err := PlatformCredentialList("example.org", false)
	require.NoError(t, err)
	require.Len(t, list, 1)

	for _, cred := range list {
		err = DeletePlatformCredential(cred.CredentialID)
		require.NoError(t, err)
	}
}

func TestIsUserVerifyingPlatformAuthenticatorAvailable(t *testing.T) {
	if !runWinHelloTests() {
		t.Skip("Skipping test because WINHELLO_TESTS is not set")
	}

	available, err := IsUserVerifyingPlatformAuthenticatorAvailable()
	require.NoError(t, err)

	assert.True(t, available)
}

// TestAuthenticatorMakeCrossPlatformCredential creates a non-residential credential to save space on authenticator.
func TestAuthenticatorMakeCrossPlatformCredential(t *testing.T) {
	if !runWinHelloTests() {
		t.Skip("Skipping test because WINHELLO_TESTS is not set")
	}

	credAttestation, err := MakeCredential(
		hWnd,
		[]byte("{}"),
		credential.PublicKeyCredentialRpEntity{
			ID:   "example.org",
			Name: "Example RP",
		},
		credential.PublicKeyCredentialUserEntity{
			ID:          []byte("john"),
			Name:        "John Doe",
			DisplayName: "John Doe",
		},
		[]credential.PublicKeyCredentialParameters{
			{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			},
		},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialPropertiesInputs: &webauthn.CreateCredentialPropertiesInputs{
				CredentialProperties: true,
			},
		},
		&AuthenticatorMakeCredentialOptions{
			AuthenticatorAttachment:         WinHelloAuthenticatorAttachmentCrossPlatform,
			AttestationConveyancePreference: WinHelloAttestationConveyancePreferenceDirect,
		},
	)
	require.NoError(t, err)

	// credProps
	assert.Equal(t, new(false), credAttestation.ExtensionOutputs.CredentialProperties.ResidentKey)

	godump.Dump(credAttestation)
}

// TestAuthenticatorGetCrossPlatformAssertion uses previously created credential ID to test deterministic PRF output.
// Value was compared with various
func TestAuthenticatorGetCrossPlatformAssertion(t *testing.T) {
	if !runWinHelloTests() {
		t.Skip("Skipping test because WINHELLO_TESTS is not set")
	}

	credIDStr := "ruDDeY_rT2Jv25HOJCY5LhTUXlX1DrIaAYVTXrumUtU5qNvr9uo77UekHDMiu1TEIRgw20ptOx841RsVZl--iofFQXkc0vIZ0-gpXZtw5g138QI0a1d4WBQbF7F1PbpC"
	credID, err := base64.RawURLEncoding.DecodeString(credIDStr)
	require.NoError(t, err)

	assertion, err := GetAssertion(
		hWnd,
		"example.org",
		[]byte("{}"),
		[]credential.PublicKeyCredentialDescriptor{
			{
				ID:   credID,
				Type: credential.PublicKeyCredentialTypePublicKey,
			},
		},
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
						credIDStr: {
							First: []byte("first"),
						},
					},
				},
			},
		},
		&AuthenticatorGetAssertionOptions{
			AuthenticatorAttachment:     WinHelloAuthenticatorAttachmentCrossPlatform,
			UserVerificationRequirement: WinHelloUserVerificationRequirementDiscouraged,
			CredentialHints: []credential.PublicKeyCredentialHint{
				credential.PublicKeyCredentialHintClientDevice,
				credential.PublicKeyCredentialHintSecurityKey,
				credential.PublicKeyCredentialHintHybrid,
			},
		},
	)
	require.NoError(t, err)

	// prf
	require.NotNil(t, assertion.ExtensionOutputs.GetPRFOutputs)
	assert.Equal(
		t,
		[]byte{
			0x1d, 0x6, 0x7d, 0xaf, 0x7e, 0xec, 0xc2, 0x17,
			0x1b, 0x24, 0x4d, 0xc8, 0x52, 0x1, 0x18, 0x1f,
			0x92, 0xc, 0xe0, 0xcc, 0xcd, 0xa5, 0x6b, 0x9e,
			0x12, 0xfc, 0x6d, 0xab, 0xaf, 0x6, 0x10, 0x5c,
		},
		assertion.ExtensionOutputs.PRF.Results.First,
	)

	godump.Dump(assertion)
}

func TestAuthenticatorList(t *testing.T) {
	if !runWinHelloTests() {
		t.Skip("Skipping test because WINHELLO_TESTS is not set")
	}

	list, err := AuthenticatorList()
	require.NoError(t, err)

	for _, auth := range list {
		godump.Dump(auth)
	}
}
