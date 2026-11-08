# telesma-app/winhello

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/winhello.svg)](https://pkg.go.dev/github.com/go-ctap/winhello)
[![Go](https://github.com/telesma-app/winhello/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/winhello/actions/workflows/go.yml)

`telesma-app/winhello` provides cgo-free Go bindings to the Windows WebAuthn API
for Windows Hello biometrics and external security keys.

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Features

- WebAuthn credential creation, assertions and platform credential management.
- Windows Hello availability and WebAuthn API version queries.
- WebAuthn extensions including `hmac-secret`, `prf` and `credBlob`.
- Native Windows calls without a C toolchain.
- A `hiddenwindow` package for operations requiring a window handle.

## Platform support

64-bit Windows 10 or later (`amd64` and `arm64`), with Go 1.27.3 or later.
Individual API methods and extensions depend on the Windows WebAuthn API version
and the selected authenticator.

The native declarations follow Microsoft's [`webauthn.h` API 9](https://github.com/microsoft/webauthn/blob/0ef86c2fe31e5b0608cc4fce4820935bd644cabb/webauthn.h).
`APIVersionNumber()` reports the API available on the running Windows version.

| Feature | Minimum WebAuthn API |
| --- | --- |
| Credential creation, assertions, cancellation, `hmac-secret` creation | 1 |
| `credProtect` | 2 |
| `credBlob`, `minPinLength`, known `credProps.rk` | 3 |
| Platform credential listing/deletion, PRF/HMAC assertion inputs | 4 |
| Large blob support through the native operation options | 5 |
| PRF enablement during registration | 6 |
| Registration-time PRF/HMAC evaluation, credential hints | 8 |
| Authenticator listing, remote origin and response JSON fields | 9 |

For older APIs, an unavailable `credProps.rk` is returned as nil. Listing and
deletion methods return a DLL lookup error when their native API is unavailable.
Use `U2FAppIDUsed` on an assertion response to determine whether Windows used the
requested U2F AppID instead of the relying party ID.

This package wraps the WebAuthn client APIs. Microsoft's passkey-provider plugin
interfaces are a separate API family.

## Installation

```sh
go get github.com/go-ctap/winhello@latest
```

The module path remains `github.com/go-ctap/winhello`; use that path for imports.
See [`go.mod`](go.mod) for the required Go version.

Credential and extension types come from [`github.com/telesma-app/ctap`](https://github.com/telesma-app/ctap):
`credential` contains credential entities and transports, `webauthn` contains client
extension inputs and outputs, and `protocol` contains parsed authenticator data.

## Quick start

On Windows, query the native API version and Windows Hello availability:

```go
package main

import (
	"fmt"
	"log"

	"github.com/go-ctap/winhello"
)

func main() {
	fmt.Printf("WebAuthn API version: %d\n", winhello.APIVersionNumber())

	available, err := winhello.IsUserVerifyingPlatformAuthenticatorAvailable()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Windows Hello available: %t\n", available)
}
```

## Examples

[`example/main.go`](example/main.go) demonstrates `GetAssertion`, a hidden window
and PRF inputs. Adapt its relying party, client data and credential ID to an
existing credential in your application.

## API coverage

- [x] WebAuthNAuthenticatorGetAssertion
    - [x] WebAuthNFreeAssertion
- [x] WebAuthNAuthenticatorMakeCredential
    - [x] WebAuthNFreeCredentialAttestation
- [x] WebAuthNCancelCurrentOperation
- [x] WebAuthNDeletePlatformCredential
- [x] WebAuthNGetApiVersionNumber
- [x] WebAuthNGetCancellationId
- [x] WebAuthNGetAuthenticatorList
    - [x] WebAuthNFreeAuthenticatorList
- [x] WebAuthNGetErrorName
- [x] WebAuthNGetPlatformCredentialList
    - [x] WebAuthNFreePlatformCredentialList
- [x] WebAuthNGetW3CExceptionDOMError
- [x] WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable

## Development

Run tests and static checks in PowerShell on Windows:

```powershell
go test ./...
go vet ./...
go mod tidy -diff
```

The default test run includes tests for native response conversion, PRF inputs
and hidden window creation and cleanup. ABI tests compare all native structure
sizes, alignments and field offsets with the official Windows AMD64/ARM64 layout.
Interactive Windows Hello and security key tests are opt-in:

```powershell
$env:WINHELLO_TESTS = '1'
go test -v .
```

These interactive tests use `example.org`, include credential creation and
deletion, and some require the credential ID recorded in the test source.
Run them with a test authenticator or Windows account.

On macOS or Linux, run the platform-independent tests and cross-compile Windows:

```sh
go test ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build ./...
```

If a parent `go.work` does not include this module, add it to the workspace or set
`GOWORK=off` for these commands to check the standalone module.

CI runs tests and `go vet` on Windows and Linux, checks formatting and module
consistency, and cross-compiles Windows ARM64.

## Migrating from the ctaphid-based API

- Replace `github.com/go-ctap/ctaphid/pkg/webauthntypes` imports with the appropriate
  `github.com/telesma-app/ctap/credential`, `webauthn`, `extension` or `attestation`
  package. Replace `pkg/ctaptypes` with `protocol` and COSE algorithms with `cose`.
- `CancelCurrentOperation(id *windows.GUID) error` takes the ID returned by
  `CancellationID()`. Pass the same ID in the operation's `CancellationID` option.
- `W3CExceptionDOMError(hr windows.Handle) windows.Handle` maps an HRESULT directly.
- `PRF.Eval` is a value; leave its zero value to enable PRF without evaluation.
  Assertion results use `GetPRFOutputs`; registration results use `CreatePRFOutputs`.
- `CredentialProperties.ResidentKey` is now `*bool` in CTAP client extension outputs.

## License

[Apache License 2.0](LICENSE).
