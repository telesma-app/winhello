//go:build amd64 || arm64

package winhello

import (
	"reflect"
	"strings"
	"testing"
)

func TestWindowsABILayout(t *testing.T) {
	// Sizes, alignments and offsets were computed by Clang for both Windows amd64
	// and arm64 from microsoft/webauthn at 0ef86c2fe31e5b0608cc4fce4820935bd644cabb.
	// https://github.com/microsoft/webauthn/blob/0ef86c2fe31e5b0608cc4fce4820935bd644cabb/webauthn.h
	for _, tt := range []struct {
		typ         reflect.Type
		size, align uintptr
		fields      map[string]struct{ offset, size uintptr }
	}{
		{
			typ: reflect.TypeFor[_GUID](), size: 16, align: 4,
			fields: map[string]struct{ offset, size uintptr }{
				"Data1": {offset: 0, size: 4},
				"Data2": {offset: 4, size: 2},
				"Data3": {offset: 6, size: 2},
				"Data4": {offset: 8, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_RP_ENTITY_INFORMATION](), size: 32, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion": {offset: 0, size: 4},
				"PwszId":    {offset: 8, size: 8},
				"PwszName":  {offset: 16, size: 8},
				"PwszIcon":  {offset: 24, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_USER_ENTITY_INFORMATION](), size: 40, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":       {offset: 0, size: 4},
				"CbId":            {offset: 4, size: 4},
				"PbId":            {offset: 8, size: 8},
				"PwszName":        {offset: 16, size: 8},
				"PwszIcon":        {offset: 24, size: 8},
				"PwszDisplayName": {offset: 32, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CLIENT_DATA](), size: 24, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":        {offset: 0, size: 4},
				"CbClientDataJSON": {offset: 4, size: 4},
				"PbClientDataJSON": {offset: 8, size: 8},
				"PwszHashAlgId":    {offset: 16, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_COSE_CREDENTIAL_PARAMETER](), size: 24, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":          {offset: 0, size: 4},
				"PwszCredentialType": {offset: 8, size: 8},
				"LAlg":               {offset: 16, size: 4},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_COSE_CREDENTIAL_PARAMETERS](), size: 16, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CCredentialParameters": {offset: 0, size: 4},
				"PCredentialParameters": {offset: 8, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CREDENTIAL](), size: 24, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":          {offset: 0, size: 4},
				"CbId":               {offset: 4, size: 4},
				"PbId":               {offset: 8, size: 8},
				"PwszCredentialType": {offset: 16, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CREDENTIALS](), size: 16, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CCredentials": {offset: 0, size: 4},
				"PCredentials": {offset: 8, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CREDENTIAL_EX](), size: 32, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":          {offset: 0, size: 4},
				"CbId":               {offset: 4, size: 4},
				"PbId":               {offset: 8, size: 8},
				"PwszCredentialType": {offset: 16, size: 8},
				"DwTransports":       {offset: 24, size: 4},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CREDENTIAL_LIST](), size: 16, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CCredentials":  {offset: 0, size: 4},
				"PpCredentials": {offset: 8, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_CTAPCBOR_HYBRID_STORAGE_LINKED_DATA](), size: 80, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":                  {offset: 0, size: 4},
				"CbContactId":                {offset: 4, size: 4},
				"PbContactId":                {offset: 8, size: 8},
				"CbLinkId":                   {offset: 16, size: 4},
				"PbLinkId":                   {offset: 24, size: 8},
				"CbLinkSecret":               {offset: 32, size: 4},
				"PbLinkSecret":               {offset: 40, size: 8},
				"CbPublicKey":                {offset: 48, size: 4},
				"PbPublicKey":                {offset: 56, size: 8},
				"PwszAuthenticatorName":      {offset: 64, size: 8},
				"WEncodedTunnelServerDomain": {offset: 72, size: 2},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS](), size: 4, align: 4,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion": {offset: 0, size: 4},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_AUTHENTICATOR_DETAILS](), size: 48, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":             {offset: 0, size: 4},
				"CbAuthenticatorId":     {offset: 4, size: 4},
				"PbAuthenticatorId":     {offset: 8, size: 8},
				"PwszAuthenticatorName": {offset: 16, size: 8},
				"CbAuthenticatorLogo":   {offset: 24, size: 4},
				"PbAuthenticatorLogo":   {offset: 32, size: 8},
				"BLocked":               {offset: 40, size: 4},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_AUTHENTICATOR_DETAILS_LIST](), size: 16, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CAuthenticatorDetails":  {offset: 0, size: 4},
				"PpAuthenticatorDetails": {offset: 8, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CREDENTIAL_DETAILS](), size: 72, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":             {offset: 0, size: 4},
				"CbCredentialID":        {offset: 4, size: 4},
				"PbCredentialID":        {offset: 8, size: 8},
				"PRpInformation":        {offset: 16, size: 8},
				"PUserInformation":      {offset: 24, size: 8},
				"BRemovable":            {offset: 32, size: 4},
				"BBackedUp":             {offset: 36, size: 4},
				"PwszAuthenticatorName": {offset: 40, size: 8},
				"CbAuthenticatorLogo":   {offset: 48, size: 4},
				"PbAuthenticatorLogo":   {offset: 56, size: 8},
				"BThirdPartyPayment":    {offset: 64, size: 4},
				"DwTransports":          {offset: 68, size: 4},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CREDENTIAL_DETAILS_LIST](), size: 16, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CCredentialDetails":  {offset: 0, size: 4},
				"PpCredentialDetails": {offset: 8, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_GET_CREDENTIALS_OPTIONS](), size: 24, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":             {offset: 0, size: 4},
				"PwszRpId":              {offset: 8, size: 8},
				"BBrowserInPrivateMode": {offset: 16, size: 4},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_HMAC_SECRET_SALT](), size: 32, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CbFirst":  {offset: 0, size: 4},
				"PbFirst":  {offset: 8, size: 8},
				"CbSecond": {offset: 16, size: 4},
				"PbSecond": {offset: 24, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT](), size: 24, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CbCredID":        {offset: 0, size: 4},
				"PbCredID":        {offset: 8, size: 8},
				"PHmacSecretSalt": {offset: 16, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_HMAC_SECRET_SALT_VALUES](), size: 24, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"PGlobalHmacSalt":             {offset: 0, size: 8},
				"CCredWithHmacSecretSaltList": {offset: 8, size: 4},
				"PCredWithHmacSecretSaltList": {offset: 16, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CRED_PROTECT_EXTENSION_IN](), size: 8, align: 4,
			fields: map[string]struct{ offset, size uintptr }{
				"DwCredProtect":       {offset: 0, size: 4},
				"BRequireCredProtect": {offset: 4, size: 4},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CRED_BLOB_EXTENSION](), size: 16, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CbCredBlob": {offset: 0, size: 4},
				"PbCredBlob": {offset: 8, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_EXTENSION](), size: 24, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"PwszExtensionIdentifier": {offset: 0, size: 8},
				"CbExtension":             {offset: 8, size: 4},
				"PvExtension":             {offset: 16, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_EXTENSIONS](), size: 16, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CExtensions": {offset: 0, size: 4},
				"PExtensions": {offset: 8, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS](), size: 200, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":                                {offset: 0, size: 4},
				"DwTimeoutMilliseconds":                    {offset: 4, size: 4},
				"CredentialList":                           {offset: 8, size: 16},
				"Extensions":                               {offset: 24, size: 16},
				"DwAuthenticatorAttachment":                {offset: 40, size: 4},
				"BRequireResidentKey":                      {offset: 44, size: 4},
				"DwUserVerificationRequirement":            {offset: 48, size: 4},
				"DwAttestationConveyancePreference":        {offset: 52, size: 4},
				"DwFlags":                                  {offset: 56, size: 4},
				"PCancellationId":                          {offset: 64, size: 8},
				"PExcludeCredentialList":                   {offset: 72, size: 8},
				"DwEnterpriseAttestation":                  {offset: 80, size: 4},
				"DwLargeBlobSupport":                       {offset: 84, size: 4},
				"BPreferResidentKey":                       {offset: 88, size: 4},
				"BBrowserInPrivateMode":                    {offset: 92, size: 4},
				"BEnablePrf":                               {offset: 96, size: 4},
				"PLinkedDevice":                            {offset: 104, size: 8},
				"CbJsonExt":                                {offset: 112, size: 4},
				"PbJsonExt":                                {offset: 120, size: 8},
				"PPRFGlobalEval":                           {offset: 128, size: 8},
				"CCredentialHints":                         {offset: 136, size: 4},
				"PpwszCredentialHints":                     {offset: 144, size: 8},
				"BThirdPartyPayment":                       {offset: 152, size: 4},
				"PwszRemoteWebOrigin":                      {offset: 160, size: 8},
				"CbPublicKeyCredentialCreationOptionsJSON": {offset: 168, size: 4},
				"PbPublicKeyCredentialCreationOptionsJSON": {offset: 176, size: 8},
				"CbAuthenticatorId":                        {offset: 184, size: 4},
				"PbAuthenticatorId":                        {offset: 192, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS](), size: 200, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":                     {offset: 0, size: 4},
				"DwTimeoutMilliseconds":         {offset: 4, size: 4},
				"CredentialList":                {offset: 8, size: 16},
				"Extensions":                    {offset: 24, size: 16},
				"DwAuthenticatorAttachment":     {offset: 40, size: 4},
				"DwUserVerificationRequirement": {offset: 44, size: 4},
				"DwFlags":                       {offset: 48, size: 4},
				"PwszU2fAppId":                  {offset: 56, size: 8},
				"PbU2fAppId":                    {offset: 64, size: 8},
				"PCancellationId":               {offset: 72, size: 8},
				"PAllowCredentialList":          {offset: 80, size: 8},
				"DwCredLargeBlobOperation":      {offset: 88, size: 4},
				"CbCredLargeBlob":               {offset: 92, size: 4},
				"PbCredLargeBlob":               {offset: 96, size: 8},
				"PHmacSecretSaltValues":         {offset: 104, size: 8},
				"BBrowserInPrivateMode":         {offset: 112, size: 4},
				"PLinkedDevice":                 {offset: 120, size: 8},
				"BAutoFill":                     {offset: 128, size: 4},
				"CbJsonExt":                     {offset: 132, size: 4},
				"PbJsonExt":                     {offset: 136, size: 8},
				"CCredentialHints":              {offset: 144, size: 4},
				"PpwszCredentialHints":          {offset: 152, size: 8},
				"PwszRemoteWebOrigin":           {offset: 160, size: 8},
				"CbPublicKeyCredentialRequestOptionsJSON": {offset: 168, size: 4},
				"PbPublicKeyCredentialRequestOptionsJSON": {offset: 176, size: 8},
				"CbAuthenticatorId":                       {offset: 184, size: 4},
				"PbAuthenticatorId":                       {offset: 192, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_X5C](), size: 16, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"CbData": {offset: 0, size: 4},
				"PbData": {offset: 8, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_COMMON_ATTESTATION](), size: 88, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":   {offset: 0, size: 4},
				"PwszAlg":     {offset: 8, size: 8},
				"LAlg":        {offset: 16, size: 4},
				"CbSignature": {offset: 20, size: 4},
				"PbSignature": {offset: 24, size: 8},
				"CX5c":        {offset: 32, size: 4},
				"PX5c":        {offset: 40, size: 8},
				"PwszVer":     {offset: 48, size: 8},
				"CbCertInfo":  {offset: 56, size: 4},
				"PbCertInfo":  {offset: 64, size: 8},
				"CbPubArea":   {offset: 72, size: 4},
				"PbPubArea":   {offset: 80, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_CREDENTIAL_ATTESTATION](), size: 192, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":                  {offset: 0, size: 4},
				"PwszFormatType":             {offset: 8, size: 8},
				"CbAuthenticatorData":        {offset: 16, size: 4},
				"PbAuthenticatorData":        {offset: 24, size: 8},
				"CbAttestation":              {offset: 32, size: 4},
				"PbAttestation":              {offset: 40, size: 8},
				"DwAttestationDecodeType":    {offset: 48, size: 4},
				"PvAttestationDecode":        {offset: 56, size: 8},
				"CbAttestationObject":        {offset: 64, size: 4},
				"PbAttestationObject":        {offset: 72, size: 8},
				"CbCredentialId":             {offset: 80, size: 4},
				"PbCredentialId":             {offset: 88, size: 8},
				"Extensions":                 {offset: 96, size: 16},
				"DwUsedTransport":            {offset: 112, size: 4},
				"BEpAtt":                     {offset: 116, size: 4},
				"BLargeBlobSupported":        {offset: 120, size: 4},
				"BResidentKey":               {offset: 124, size: 4},
				"BPrfEnabled":                {offset: 128, size: 4},
				"CbUnsignedExtensionOutputs": {offset: 132, size: 4},
				"PbUnsignedExtensionOutputs": {offset: 136, size: 8},
				"PHmacSecret":                {offset: 144, size: 8},
				"BThirdPartyPayment":         {offset: 152, size: 4},
				"DwTransports":               {offset: 156, size: 4},
				"CbClientDataJSON":           {offset: 160, size: 4},
				"PbClientDataJSON":           {offset: 168, size: 8},
				"CbRegistrationResponseJSON": {offset: 176, size: 4},
				"PbRegistrationResponseJSON": {offset: 184, size: 8},
			},
		},
		{
			typ: reflect.TypeFor[_WEBAUTHN_ASSERTION](), size: 168, align: 8,
			fields: map[string]struct{ offset, size uintptr }{
				"DwVersion":                    {offset: 0, size: 4},
				"CbAuthenticatorData":          {offset: 4, size: 4},
				"PbAuthenticatorData":          {offset: 8, size: 8},
				"CbSignature":                  {offset: 16, size: 4},
				"PbSignature":                  {offset: 24, size: 8},
				"Credential":                   {offset: 32, size: 24},
				"CbUserId":                     {offset: 56, size: 4},
				"PbUserId":                     {offset: 64, size: 8},
				"Extensions":                   {offset: 72, size: 16},
				"CbCredLargeBlob":              {offset: 88, size: 4},
				"PbCredLargeBlob":              {offset: 96, size: 8},
				"DwCredLargeBlobStatus":        {offset: 104, size: 4},
				"PHmacSecret":                  {offset: 112, size: 8},
				"DwUsedTransport":              {offset: 120, size: 4},
				"CbUnsignedExtensionOutputs":   {offset: 124, size: 4},
				"PbUnsignedExtensionOutputs":   {offset: 128, size: 8},
				"CbClientDataJSON":             {offset: 136, size: 4},
				"PbClientDataJSON":             {offset: 144, size: 8},
				"CbAuthenticationResponseJSON": {offset: 152, size: 4},
				"PbAuthenticationResponseJSON": {offset: 160, size: 8},
			},
		},
	} {
		t.Run(tt.typ.Name(), func(t *testing.T) {
			if tt.typ.Size() != tt.size || uintptr(tt.typ.Align()) != tt.align {
				t.Errorf("size/alignment = %d/%d, want %d/%d", tt.typ.Size(), tt.typ.Align(), tt.size, tt.align)
			}

			count := 0

			for i := 0; i < tt.typ.NumField(); i++ {
				if !strings.HasPrefix(tt.typ.Field(i).Name, "Pad_cgo_") {
					count++
				}
			}

			if count != len(tt.fields) {
				t.Errorf("field count = %d, want %d", count, len(tt.fields))
			}

			for name, want := range tt.fields {
				field, ok := tt.typ.FieldByName(name)
				if !ok {
					t.Errorf("missing field %s", name)
					continue
				}

				if field.Offset != want.offset || field.Type.Size() != want.size {
					t.Errorf("%s offset/size = %d/%d, want %d/%d", name, field.Offset, field.Type.Size(), want.offset, want.size)
				}
			}
		})
	}
}
