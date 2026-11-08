package winhello

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/webauthn"
	"golang.org/x/sys/windows"
)

func TestCreateExtensionValidation(t *testing.T) {
	for _, tt := range []struct {
		name   string
		inputs webauthn.CreateAuthenticationExtensionsClientInputs
		want   string
	}{
		{"PRF_second_without_first", webauthn.CreateAuthenticationExtensionsClientInputs{PRFInputs: &webauthn.PRFInputs{PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: webauthn.AuthenticationExtensionsPRFValues{Second: []byte{}}}}}, "prf.first"},
		{"PRF_credential_map", webauthn.CreateAuthenticationExtensionsClientInputs{PRFInputs: &webauthn.PRFInputs{PRF: webauthn.AuthenticationExtensionsPRFInputs{EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{}}}}, "prf.evalByCredential"},
		{"PRF_and_raw_HMAC", webauthn.CreateAuthenticationExtensionsClientInputs{PRFInputs: &webauthn.PRFInputs{}, CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{}}, "hmac-secret-mc and prf"},
		{"HMAC_missing_salt", webauthn.CreateAuthenticationExtensionsClientInputs{CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{}}, "salt1"},
		{"HMAC_empty_second", webauthn.CreateAuthenticationExtensionsClientInputs{CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32), Salt2: []byte{}}}}, "salt2"},
		{"invalid_credProtect", webauthn.CreateAuthenticationExtensionsClientInputs{CreateCredentialProtectionInputs: &webauthn.CreateCredentialProtectionInputs{CredentialProtectionPolicy: "invalid"}}, "credentialProtectionPolicy"},
		{"largeBlob_read", webauthn.CreateAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(false)}}}, "only valid for GetAssertion"},
		{"largeBlob_empty_write", webauthn.CreateAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Write: []byte{}}}}, "only valid for GetAssertion"},
		{"largeBlob_invalid_support", webauthn.CreateAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Support: "invalid"}}}, "largeBlob.support"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Validation must fail before a native call, even with no usable RP/user.
			resp, err := MakeCredential(0, nil, credential.PublicKeyCredentialRpEntity{}, credential.PublicKeyCredentialUserEntity{}, nil, nil, &tt.inputs, nil)
			require.ErrorContains(t, err, tt.want)
			assert.Nil(t, resp)
		})
	}
}

func TestGetPRFValidation(t *testing.T) {
	allowed := []credential.PublicKeyCredentialDescriptor{{ID: []byte{0xfb}}}
	for _, tt := range []struct {
		name      string
		inputs    webauthn.AuthenticationExtensionsPRFInputs
		allowList []credential.PublicKeyCredentialDescriptor
	}{
		{"missing_first", webauthn.AuthenticationExtensionsPRFInputs{Eval: webauthn.AuthenticationExtensionsPRFValues{Second: []byte{}}}, allowed},
		{"missing_allow_list", webauthn.AuthenticationExtensionsPRFInputs{EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{"-w": {First: []byte{}}}}, nil},
		{"unknown_credential", webauthn.AuthenticationExtensionsPRFInputs{EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{"AQ": {First: []byte{}}}}, allowed},
		{"empty_id", webauthn.AuthenticationExtensionsPRFInputs{EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{"": {First: []byte{}}}}, allowed},
		{"padded_id", webauthn.AuthenticationExtensionsPRFInputs{EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{"-w==": {First: []byte{}}}}, allowed},
		{"noncanonical_id", webauthn.AuthenticationExtensionsPRFInputs{EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{"-x": {First: []byte{}}}}, allowed},
		{"missing_credential_first", webauthn.AuthenticationExtensionsPRFInputs{EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{"-w": {}}}, allowed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := getAssertionOptions(tt.allowList, &webauthn.GetAuthenticationExtensionsClientInputs{PRFInputs: &webauthn.PRFInputs{PRF: tt.inputs}}, nil)
			require.Error(t, err)
			assert.Nil(t, opts)
		})
	}
}

func TestPRFPassesUnhashedEmptyAndCredentialSpecificInputs(t *testing.T) {
	inputs := webauthn.AuthenticationExtensionsPRFInputs{
		Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte{}, Second: []byte{}},
		EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
			"AQ": {First: []byte("one")}, "Ag": {First: []byte("two"), Second: []byte{}},
		},
	}
	opts, err := getAssertionOptions([]credential.PublicKeyCredentialDescriptor{{ID: []byte{1}}, {ID: []byte{2}}}, &webauthn.GetAuthenticationExtensionsClientInputs{PRFInputs: &webauthn.PRFInputs{PRF: inputs}}, nil)
	require.NoError(t, err)
	assert.Zero(t, opts.DwFlags) // Windows applies the PRF domain hash.
	global := opts.PHmacSecretSaltValues.PGlobalHmacSalt
	require.NotNil(t, global)
	assert.Zero(t, global.CbFirst)
	assert.NotNil(t, global.PbFirst)
	assert.Zero(t, global.CbSecond)
	assert.NotNil(t, global.PbSecond)

	entries := unsafe.Slice(opts.PHmacSecretSaltValues.PCredWithHmacSecretSaltList, opts.PHmacSecretSaltValues.CCredWithHmacSecretSaltList)
	require.Len(t, entries, 2)

	for _, entry := range entries {
		id := *entry.PbCredID
		salt := entry.PHmacSecretSalt

		want := []byte("one")
		if id == 2 {
			want = []byte("two")

			assert.NotNil(t, salt.PbSecond)
		} else {
			assert.Nil(t, salt.PbSecond)
		}

		assert.Equal(t, want, unsafe.Slice(salt.PbFirst, salt.CbFirst))
	}

	create := &webauthn.CreateAuthenticationExtensionsClientInputs{PRFInputs: &webauthn.PRFInputs{PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: inputs.Eval}}}
	require.NoError(t, validateMakeCredentialExtensions(create, nil))
	native := makeCredentialOptions(nil, create, nil)
	assert.NotNil(t, native.PPRFGlobalEval.PbFirst)
	assert.NotNil(t, native.PPRFGlobalEval.PbSecond)
	assert.Zero(t, native.DwFlags)
}

func TestGetHMACSaltValidation(t *testing.T) {
	for _, salts := range []webauthn.HMACGetSecretInput{
		{}, {Salt1: make([]byte, 31)}, {Salt1: make([]byte, 33)},
		{Salt1: make([]byte, 32), Salt2: []byte{}},
		{Salt1: make([]byte, 32), Salt2: make([]byte, 31)},
	} {
		_, err := getAssertionOptions(nil, &webauthn.GetAuthenticationExtensionsClientInputs{GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{HMACGetSecret: salts}}, nil)
		require.Error(t, err)
	}

	inputs := &webauthn.GetAuthenticationExtensionsClientInputs{GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: bytes.Repeat([]byte{1}, 32)}}}
	opts, err := getAssertionOptions(nil, inputs, nil)
	require.NoError(t, err)
	assert.Equal(t, uint32(WinHelloAuthenticatorHMACSecretValuesFlag), opts.DwFlags)

	inputs.PRFInputs = &webauthn.PRFInputs{}
	_, err = getAssertionOptions(nil, inputs, nil)
	require.Error(t, err)
}

func TestLargeBlobOptions(t *testing.T) {
	for _, tt := range []struct {
		support extension.LargeBlobSupport
		want    WinHelloLargeBlobSupport
	}{{"", WinHelloLargeBlobSupportPreferred}, {extension.LargeBlobSupportPreferred, WinHelloLargeBlobSupportPreferred}, {extension.LargeBlobSupportRequired, WinHelloLargeBlobSupportRequired}} {
		inputs := &webauthn.CreateAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Support: tt.support}}}

		for _, preferResidentKey := range []bool{false, true} {
			resident := &AuthenticatorMakeCredentialOptions{RequireResidentKey: true, PreferResidentKey: preferResidentKey}
			require.NoError(t, validateMakeCredentialExtensions(inputs, resident))
			native := makeCredentialOptions(nil, inputs, resident)
			assert.Equal(t, uint32(tt.want), native.DwLargeBlobSupport)
			assert.Equal(t, int32(1), native.BRequireResidentKey)
			assert.Equal(t, boolToInt32(preferResidentKey), native.BPreferResidentKey)
		}

		for _, opts := range []*AuthenticatorMakeCredentialOptions{nil, {}, {PreferResidentKey: true}} {
			err := validateMakeCredentialExtensions(inputs, opts)
			if tt.support == extension.LargeBlobSupportRequired {
				require.ErrorIs(t, err, errors.ErrUnsupported)
			} else {
				require.NoError(t, err)
				assert.Zero(t, makeCredentialOptions(nil, inputs, opts).DwLargeBlobSupport)
			}
		}

		require.Error(t, validateMakeCredentialExtensions(inputs, &AuthenticatorMakeCredentialOptions{LargeBlobSupport: WinHelloLargeBlobSupportPreferred}))
	}

	allow := []credential.PublicKeyCredentialDescriptor{{ID: []byte{1}}}

	for _, tt := range []struct {
		input     webauthn.AuthenticationExtensionsLargeBlobInputs
		operation WinHelloCredentialLargeBlobOperation
	}{{webauthn.AuthenticationExtensionsLargeBlobInputs{}, WinHelloCredentialLargeBlobOperationNone},
		{webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(false)}, WinHelloCredentialLargeBlobOperationNone},
		{webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)}, WinHelloCredentialLargeBlobOperationGet},
		{webauthn.AuthenticationExtensionsLargeBlobInputs{Write: []byte{}}, WinHelloCredentialLargeBlobOperationSet},
		{webauthn.AuthenticationExtensionsLargeBlobInputs{Write: []byte("data")}, WinHelloCredentialLargeBlobOperationSet}} {
		inputs := &webauthn.GetAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: tt.input}}
		native, err := getAssertionOptions(allow, inputs, nil)
		require.NoError(t, err)
		assert.Equal(t, uint32(tt.operation), native.DwCredLargeBlobOperation)

		if tt.input.Write != nil {
			assert.NotNil(t, native.PbCredLargeBlob)
			assert.Equal(t, tt.input.Write, unsafe.Slice(native.PbCredLargeBlob, native.CbCredLargeBlob))
		}

		_, err = getAssertionOptions(allow, inputs, &AuthenticatorGetAssertionOptions{CredentialLargeBlobOperation: WinHelloCredentialLargeBlobOperationDelete})
		require.Error(t, err)
	}

	for _, input := range []webauthn.AuthenticationExtensionsLargeBlobInputs{
		{Support: extension.LargeBlobSupportPreferred}, {Read: new(false), Write: []byte{}}, {Write: []byte{}},
	} {
		_, err := getAssertionOptions(nil, &webauthn.GetAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: input}}, nil)
		require.Error(t, err)
	}
}

func TestLargeBlobOutputs(t *testing.T) {
	authData := make([]byte, 37)

	authData[32] = 1
	for _, supported := range []bool{false, true} {
		native := _WEBAUTHN_CREDENTIAL_ATTESTATION{
			DwVersion: 4, PwszFormatType: windows.StringToUTF16Ptr("none"),
			CbAuthenticatorData: uint32(len(authData)), PbAuthenticatorData: unsafe.SliceData(authData), BLargeBlobSupported: boolToInt32(supported),
		}
		resp, err := native.ToMakeCredentialResponse(&webauthn.CreateAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{}})
		require.NoError(t, err)
		require.NotNil(t, resp.ExtensionOutputs.LargeBlobOutputs)
		assert.Equal(t, new(supported), resp.ExtensionOutputs.LargeBlob.Supported)
	}

	for _, status := range []WinHelloCredentialLargeBlobStatus{WinHelloCredentialLargeBlobStatusSuccess, WinHelloCredentialLargeBlobStatusNotFound, WinHelloCredentialLargeBlobStatusNotSupported, WinHelloCredentialLargeBlobStatusNone} {
		for _, data := range [][]byte{nil, []byte("saved data")} {
			buffer := bytes.Clone(data)
			native := _WEBAUTHN_ASSERTION{DwVersion: 2, CbAuthenticatorData: uint32(len(authData)), PbAuthenticatorData: unsafe.SliceData(authData), DwCredLargeBlobStatus: uint32(status), CbCredLargeBlob: uint32(len(buffer)), PbCredLargeBlob: unsafe.SliceData(buffer)}
			read, err := native.ToGetAssertionResponse(&webauthn.GetAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)}}})
			require.NoError(t, err)
			require.NotNil(t, read.ExtensionOutputs.LargeBlobOutputs)
			clear(buffer)

			if status == WinHelloCredentialLargeBlobStatusSuccess {
				assert.NotNil(t, read.ExtensionOutputs.LargeBlob.Blob)
				assert.Equal(t, append([]byte{}, data...), read.ExtensionOutputs.LargeBlob.Blob)
			} else {
				assert.Nil(t, read.ExtensionOutputs.LargeBlob.Blob)
			}

			write, err := native.ToGetAssertionResponse(&webauthn.GetAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Write: []byte{}}}})
			require.NoError(t, err)
			assert.Equal(t, new(status == WinHelloCredentialLargeBlobStatusSuccess), write.ExtensionOutputs.LargeBlob.Written)
			noop, err := native.ToGetAssertionResponse(&webauthn.GetAuthenticationExtensionsClientInputs{LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(false)}}})
			require.NoError(t, err)
			assert.Nil(t, noop.ExtensionOutputs.LargeBlobOutputs)
		}
	}
}

func TestUnsupportedExtensionsAndPaymentRegistration(t *testing.T) {
	for _, inputs := range []*webauthn.CreateAuthenticationExtensionsClientInputs{
		{PreviewSignInputs: &webauthn.PreviewSignInputs{}},
		{CreatePinComplexityPolicyInputs: &webauthn.CreatePinComplexityPolicyInputs{PinComplexityPolicy: true}},
	} {
		require.ErrorIs(t, validateMakeCredentialExtensions(inputs, nil), errors.ErrUnsupported)
	}

	for _, inputs := range []*webauthn.GetAuthenticationExtensionsClientInputs{
		{PreviewSignInputs: &webauthn.PreviewSignInputs{}},
		{PaymentInputs: &webauthn.PaymentInputs{Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: true}}},
	} {
		_, err := getAssertionOptions(nil, inputs, nil)
		require.ErrorIs(t, err, errors.ErrUnsupported)
	}

	for _, enabled := range []bool{false, true} {
		inputs := &webauthn.CreateAuthenticationExtensionsClientInputs{PaymentInputs: &webauthn.PaymentInputs{Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: enabled}}}
		require.NoError(t, validateMakeCredentialExtensions(inputs, nil))
		assert.Equal(t, boolToInt32(enabled), makeCredentialOptions(nil, inputs, nil).BThirdPartyPayment)
	}
}
