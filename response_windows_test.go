package winhello

import (
	"bytes"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telesma-app/ctap/webauthn"
	"golang.org/x/sys/windows"
)

func TestAssertionResponseOwnsNativeBuffers(t *testing.T) {
	authData := make([]byte, 37)
	authData[32] = 1 // User present, no extensions.
	credentialID, signature := []byte{1, 2}, []byte{3, 4}
	first := bytes.Repeat([]byte{5}, 32)
	clientData, responseJSON := []byte("{}"), []byte("{\"id\":1}")
	native := _WEBAUTHN_ASSERTION{
		DwVersion:           6,
		CbAuthenticatorData: uint32(len(authData)), PbAuthenticatorData: unsafe.SliceData(authData),
		CbSignature: uint32(len(signature)), PbSignature: unsafe.SliceData(signature),
		Credential: _WEBAUTHN_CREDENTIAL{
			CbId: uint32(len(credentialID)), PbId: unsafe.SliceData(credentialID),
			PwszCredentialType: windows.StringToUTF16Ptr("public-key"),
		},
		PHmacSecret:      &_WEBAUTHN_HMAC_SECRET_SALT{CbFirst: uint32(len(first)), PbFirst: unsafe.SliceData(first)},
		DwUsedTransport:  0x03,
		CbClientDataJSON: uint32(len(clientData)), PbClientDataJSON: unsafe.SliceData(clientData),
		CbAuthenticationResponseJSON: uint32(len(responseJSON)), PbAuthenticationResponseJSON: unsafe.SliceData(responseJSON),
	}

	resp, err := native.ToGetAssertionResponse(&webauthn.GetAuthenticationExtensionsClientInputs{PRFInputs: &webauthn.PRFInputs{}})
	require.NoError(t, err)
	clear(authData)
	clear(credentialID)
	clear(signature)
	clear(first)
	clear(clientData)
	clear(responseJSON)

	assert.Equal(t, byte(1), resp.AuthDataRaw[32])
	assert.Equal(t, []byte{1, 2}, resp.Credential.ID)
	assert.Equal(t, []byte{3, 4}, resp.Signature)
	require.NotNil(t, resp.hmacSecret)
	assert.Equal(t, bytes.Repeat([]byte{5}, 32), resp.hmacSecret.First)
	require.NotNil(t, resp.ExtensionOutputs.GetPRFOutputs)
	assert.Equal(t, bytes.Repeat([]byte{5}, 32), resp.ExtensionOutputs.GetPRFOutputs.PRF.Results.First)
	assert.Equal(t, []byte("{}"), resp.ClientDataJSON)
	assert.Equal(t, []byte("{\"id\":1}"), resp.AuthenticationResponseJSON)
	assert.Len(t, resp.UsedTransport, 2)
}

func TestThirdPartyPaymentWithoutHMACSecret(t *testing.T) {
	authData := make([]byte, 37)
	authData[32] = 1
	native := _WEBAUTHN_CREDENTIAL_ATTESTATION{
		DwVersion:           7,
		PwszFormatType:      windows.StringToUTF16Ptr("none"),
		CbAuthenticatorData: uint32(len(authData)), PbAuthenticatorData: unsafe.SliceData(authData),
		BThirdPartyPayment: 1,
	}

	resp, err := native.ToMakeCredentialResponse(nil)
	require.NoError(t, err)

	assert.True(t, resp.ThirdPartyPayment)
	assert.Nil(t, resp.HMACSecret)
}

func TestCredentialPropertiesResidentKeyPresence(t *testing.T) {
	for _, tt := range []struct {
		name        string
		version     uint32
		residentKey int32
		requested   bool
		want        *bool
	}{
		{name: "unavailable_on_version_3", version: 3, requested: true},
		{name: "known_false", version: 4, requested: true, want: new(false)},
		{name: "known_true", version: 4, residentKey: 1, requested: true, want: new(true)},
		{name: "disabled", version: 4, residentKey: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authData := make([]byte, 37)
			authData[32] = 1
			native := _WEBAUTHN_CREDENTIAL_ATTESTATION{
				DwVersion:           tt.version,
				PwszFormatType:      windows.StringToUTF16Ptr("none"),
				CbAuthenticatorData: uint32(len(authData)), PbAuthenticatorData: unsafe.SliceData(authData),
				BResidentKey: tt.residentKey,
			}

			resp, err := native.ToMakeCredentialResponse(&webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateCredentialPropertiesInputs: &webauthn.CreateCredentialPropertiesInputs{CredentialProperties: tt.requested},
			})
			require.NoError(t, err)

			if !tt.requested {
				assert.Nil(t, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs)
				return
			}
			require.NotNil(t, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs)
			assert.Equal(t, tt.want, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs.CredentialProperties.ResidentKey)
		})
	}
}

func TestNativeMakeCredentialExtensionOutputs(t *testing.T) {
	authData := make([]byte, 37)
	authData[32] = 1
	hmacSecret, credBlob := int32(1), int32(0)
	extensions := []_WEBAUTHN_EXTENSION{
		{
			PwszExtensionIdentifier: windows.StringToUTF16Ptr("hmac-secret"),
			CbExtension:             4, PvExtension: (*byte)(unsafe.Pointer(&hmacSecret)),
		},
		{
			PwszExtensionIdentifier: windows.StringToUTF16Ptr("credBlob"),
			CbExtension:             4, PvExtension: (*byte)(unsafe.Pointer(&credBlob)),
		},
	}
	native := _WEBAUTHN_CREDENTIAL_ATTESTATION{
		DwVersion: 3, PwszFormatType: windows.StringToUTF16Ptr("none"),
		CbAuthenticatorData: uint32(len(authData)), PbAuthenticatorData: unsafe.SliceData(authData),
		Extensions: _WEBAUTHN_EXTENSIONS{CExtensions: uint32(len(extensions)), PExtensions: unsafe.SliceData(extensions)},
	}

	resp, err := native.ToMakeCredentialResponse(nil)
	require.NoError(t, err)

	require.NotNil(t, resp.ExtensionOutputs.CreateHMACSecretOutputs)
	assert.True(t, resp.ExtensionOutputs.CreateHMACSecretOutputs.HMACCreateSecret)
	require.NotNil(t, resp.ExtensionOutputs.CreateCredentialBlobOutputs)
	assert.False(t, resp.ExtensionOutputs.CreateCredentialBlobOutputs.CredBlob)
}

func TestNativeGetCredentialBlobOwnsBuffer(t *testing.T) {
	authData := make([]byte, 37)
	authData[32] = 1
	data := []byte{1, 2, 3}
	blob := _WEBAUTHN_CRED_BLOB_EXTENSION{CbCredBlob: uint32(len(data)), PbCredBlob: unsafe.SliceData(data)}
	ext := _WEBAUTHN_EXTENSION{
		PwszExtensionIdentifier: windows.StringToUTF16Ptr("credBlob"),
		CbExtension:             uint32(unsafe.Sizeof(blob)), PvExtension: (*byte)(unsafe.Pointer(&blob)),
	}
	native := _WEBAUTHN_ASSERTION{
		DwVersion:           2,
		CbAuthenticatorData: uint32(len(authData)), PbAuthenticatorData: unsafe.SliceData(authData),
		Extensions: _WEBAUTHN_EXTENSIONS{CExtensions: 1, PExtensions: &ext},
	}

	resp, err := native.ToGetAssertionResponse(nil)
	require.NoError(t, err)
	clear(data)

	require.NotNil(t, resp.ExtensionOutputs.GetCredentialBlobOutputs)
	assert.Equal(t, []byte{1, 2, 3}, resp.ExtensionOutputs.GetCredentialBlobOutputs.GetCredBlob)
}
