package winhello

import (
	"bytes"
	"encoding/base64"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/webauthn"
	"golang.org/x/sys/windows"
)

func TestGetAssertionPRFByCredential(t *testing.T) {
	credentialID := []byte{0xfb, 0xff}
	first, second := []byte("first"), []byte("second")
	opts, err := getAssertionOptions(
		[]credential.PublicKeyCredentialDescriptor{{
			Type:       credential.PublicKeyCredentialTypePublicKey,
			ID:         credentialID,
			Transports: []credential.AuthenticatorTransport{credential.AuthenticatorTransportSmartCard},
		}},
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{PRF: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
					base64.RawURLEncoding.EncodeToString(credentialID): {First: first, Second: second},
				},
			}},
		},
		nil,
	)
	require.NoError(t, err)

	require.NotNil(t, opts.PAllowCredentialList)
	assert.Equal(t, uint32(1), opts.PAllowCredentialList.CCredentials)
	assert.Equal(t, uint32(0x40), (*opts.PAllowCredentialList.PpCredentials).DwTransports)
	require.NotNil(t, opts.PHmacSecretSaltValues)
	assert.Nil(t, opts.PHmacSecretSaltValues.PGlobalHmacSalt)
	assert.Equal(t, uint32(1), opts.PHmacSecretSaltValues.CCredWithHmacSecretSaltList)
	entry := opts.PHmacSecretSaltValues.PCredWithHmacSecretSaltList
	require.NotNil(t, entry)
	assert.Equal(t, credentialID, unsafe.Slice(entry.PbCredID, entry.CbCredID))
	require.NotNil(t, entry.PHmacSecretSalt)
	assert.Equal(t, first, unsafe.Slice(entry.PHmacSecretSalt.PbFirst, entry.PHmacSecretSalt.CbFirst))
	assert.Equal(t, second, unsafe.Slice(entry.PHmacSecretSalt.PbSecond, entry.PHmacSecretSalt.CbSecond))
	assert.Zero(t, opts.DwFlags)
}

func TestNativeBooleanExtensionInputs(t *testing.T) {
	for _, tt := range []struct {
		name    string
		enabled bool
	}{
		{name: "disabled"},
		{name: "enabled", enabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			get, err := getAssertionOptions(nil, &webauthn.GetAuthenticationExtensionsClientInputs{
				GetCredentialBlobInputs: &webauthn.GetCredentialBlobInputs{GetCredBlob: tt.enabled},
			}, nil)
			require.NoError(t, err)

			create := makeCredentialOptions(nil, &webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateHMACSecretInputs:   &webauthn.CreateHMACSecretInputs{HMACCreateSecret: tt.enabled},
				CreateMinPinLengthInputs: &webauthn.CreateMinPinLengthInputs{MinPinLength: tt.enabled},
			}, nil)

			assert.Zero(t, create.BEnablePrf)

			if !tt.enabled {
				assert.Zero(t, get.Extensions.CExtensions)
				assert.Zero(t, create.Extensions.CExtensions)

				return
			}

			assert.Equal(t, uint32(1), get.Extensions.CExtensions)
			assert.Equal(t, uint32(2), create.Extensions.CExtensions)

			for _, exts := range []_WEBAUTHN_EXTENSIONS{get.Extensions, create.Extensions} {
				for _, ext := range unsafe.Slice(exts.PExtensions, exts.CExtensions) {
					assert.Equal(t, uint32(4), ext.CbExtension)
					assert.Equal(t, int32(1), *(*int32)(unsafe.Pointer(ext.PvExtension)))
				}
			}
		})
	}
}

func TestU2FAppIDOutputBuffer(t *testing.T) {
	opts, err := getAssertionOptions(nil, nil, &AuthenticatorGetAssertionOptions{
		U2FAppID: "https://example.org/app-id",
	})
	require.NoError(t, err)

	assert.Equal(t, "https://example.org/app-id", windows.UTF16PtrToString(opts.PwszU2fAppId))
	require.NotNil(t, opts.PbU2fAppId)
	assert.Zero(t, *opts.PbU2fAppId)
}

func TestMakeCredentialPRFOptions(t *testing.T) {
	first, second := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	for _, tt := range []struct {
		name      string
		inputs    webauthn.CreateAuthenticationExtensionsClientInputs
		wantEval  bool
		wantFlags uint32
	}{
		{"enable_only", webauthn.CreateAuthenticationExtensionsClientInputs{PRFInputs: &webauthn.PRFInputs{}}, false, 0},
		{"PRF_eval", webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{PRF: webauthn.AuthenticationExtensionsPRFInputs{
				Eval: webauthn.AuthenticationExtensionsPRFValues{First: first, Second: second},
			}},
		}, true, 0},
		{"raw_HMAC_secret_MC", webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: first, Salt2: second},
			},
		}, true, 0x00100000},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := makeCredentialOptions(nil, &tt.inputs, nil)

			assert.Equal(t, int32(1), opts.BEnablePrf)
			assert.Equal(t, tt.wantFlags, opts.DwFlags)

			if tt.wantEval {
				require.NotNil(t, opts.PPRFGlobalEval)
				assert.Equal(t, first, unsafe.Slice(opts.PPRFGlobalEval.PbFirst, opts.PPRFGlobalEval.CbFirst))
				assert.Equal(t, second, unsafe.Slice(opts.PPRFGlobalEval.PbSecond, opts.PPRFGlobalEval.CbSecond))
			} else {
				assert.Nil(t, opts.PPRFGlobalEval)
			}
		})
	}
}
