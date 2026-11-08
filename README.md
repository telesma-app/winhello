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

Windows 10 or later. Individual API methods and extensions depend on the Windows
WebAuthn API version and the selected authenticator.

## Installation

```sh
go get github.com/go-ctap/winhello@latest
```

The module path remains `github.com/go-ctap/winhello`; use that path for imports.
See [`go.mod`](go.mod) for the required Go version.

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
```

To check compilation from macOS or Linux:

```sh
GOOS=windows go build ./...
```

## License

[Apache License 2.0](LICENSE).
