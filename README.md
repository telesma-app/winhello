# telesma-app/winhello

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/winhello.svg)](https://pkg.go.dev/github.com/telesma-app/winhello)
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

64-bit Windows 10 or later (`amd64` and `arm64`).
Individual API methods and extensions depend on the Windows WebAuthn API version
and the selected authenticator.

## Installation

```sh
go get github.com/telesma-app/winhello@latest
```

The repository and Go module moved from `github.com/go-ctap/winhello` to
`github.com/telesma-app/winhello`. To update an existing project, replace the old
prefix in imports (including subpackages), run the command above, then `go mod tidy`.

See [`go.mod`](go.mod) for the required Go version.

## Quick start

On Windows, query the native API version and Windows Hello availability:

```go
package main

import (
	"fmt"
	"log"

	"github.com/telesma-app/winhello"
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

Run `go run ./cmd/example` on Windows. [`cmd/example/main.go`](cmd/example/main.go) creates a
Windows Hello passkey for `example.org`, then uses it with `GetAssertion`.
Both steps require user interaction. The example deletes its demo passkey when it finishes.
It uses placeholder client data for a local API demonstration; a real application
must supply its own client data and validate the registration and assertion responses.

### WinHello Passkey Demo

The [WinHello Passkey Demo example](cmd/gopassmanager) uses
[`pluginauthenticator.Serve`](pkg/pluginauthenticator) and stores one ES256
passkey per Windows user. It requires Windows 11 24H2 build 26100.6725 or
later, Windows Hello, and the Windows SDK's `mt.exe` on `PATH`. The staging
script embeds a manifest that suppresses the console on COM activation.

For a local browser test, enable [Developer Mode](https://learn.microsoft.com/windows/advanced-settings/developer-mode).
Run from the repository root. Use `arm64` on Windows on Arm.

```powershell
$layout = Join-Path $env:LOCALAPPDATA 'WinHelloPluginPackage'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\cmd\gopassmanager\stage-plugin.ps1 -Architecture amd64 -Destination $layout
if ($LASTEXITCODE -ne 0) { throw 'Could not stage WinHello Passkey Demo' }
Add-AppxPackage -Register (Join-Path $layout 'AppxManifest.xml') -ErrorAction Stop
$provider = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winhello-plugin.exe'
& $provider register
```

1. Enable **WinHello Passkey Demo** in **Settings > Accounts > Passkeys > Advanced options**.
2. In [WebAuthn.io](https://webauthn.io/?regUserVerification=required&attestation=none&discoverableCredential=required&regPubKeyAlgs=es256&authUserVerification=required),
   register a test username. Choose **WinHello Passkey Demo** and confirm Windows Hello.
3. Stop the provider, then authenticate with the same username in the same tab.
   Select the saved passkey in the Windows picker. Windows starts a new provider process.

   ```powershell
   Get-Process plugin | Where-Object Path -eq (Join-Path $layout 'plugin.exe') | Stop-Process
   ```

For a clean rerun, unregister the provider and remove the demo credential
at `%LOCALAPPDATA%\WinHelloDemo\credential.dat`.

For sparse MSIX, pass `-Sparse` to the staging script. Pack the resulting
`Identity` directory with `MakeAppx.exe pack /nv`, sign the package with a
trusted `CN=GoPass` certificate, and install it with
`Add-AppxPackage -Path <msix> -ExternalLocation <staged App directory>`.
Run `App\plugin.exe register`. Uninstall the loose package before switching
layouts. [Microsoft sparse MSIX guide](https://learn.microsoft.com/windows/apps/desktop/modernize/grant-identity-to-nonpackaged-apps)

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

Interactive tests create and delete credentials. Use a test authenticator or
Windows account:

```powershell
$env:WINHELLO_TESTS = '1'
go test -v .
```

Plugin integration tests require a Windows account with the test plugin installed and enabled. Set `WINHELLO_PLUGIN_TESTS=1` to run them.

To cross-compile from macOS or Linux:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build ./...
```

## License

[Apache License 2.0](LICENSE).
