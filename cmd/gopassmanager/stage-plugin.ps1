param(
    [Parameter(Mandatory)]
    [ValidateSet('amd64', 'arm64')]
    [string]$Architecture,

    [Parameter(Mandatory)]
    [string]$Destination,

    [string]$Executable,

    [switch]$Sparse
)

$ErrorActionPreference = 'Stop'
$layout = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
$package = $layout
if ($Sparse) {
    $package = Join-Path $layout 'Identity'
    $layout = Join-Path $layout 'App'
    New-Item -ItemType Directory -Path $package -Force | Out-Null
}

$plugin = Join-Path $layout 'plugin.exe'
$assets = Join-Path $layout 'Assets'
New-Item -ItemType Directory -Path $assets -Force | Out-Null

if ($Executable) {
    Copy-Item -LiteralPath $Executable -Destination $plugin -Force
} else {
    $oldGOOS = $env:GOOS
    $oldGOARCH = $env:GOARCH
    $oldCGOEnabled = $env:CGO_ENABLED
    Push-Location $PSScriptRoot
    try {
        $env:GOOS = 'windows'
        $env:GOARCH = $Architecture
        $env:CGO_ENABLED = '0'
        go build -o $plugin .
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed with exit code $LASTEXITCODE"
        }
    } finally {
        $env:GOOS = $oldGOOS
        $env:GOARCH = $oldGOARCH
        $env:CGO_ENABLED = $oldCGOEnabled
        Pop-Location
    }
}

$applicationManifest = Join-Path $PSScriptRoot 'manager.manifest'
mt.exe -nologo -manifest $applicationManifest "-outputresource:$plugin;#1"
if ($LASTEXITCODE -ne 0) {
    throw "Embedding the application manifest in $plugin failed with exit code $LASTEXITCODE"
}

foreach ($name in @('Square44x44Logo.png', 'Square150x150Logo.png', 'StoreLogo.png')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "Assets/$name") -Destination $assets -Force
}

$manifestPath = Join-Path $PSScriptRoot 'AppxManifest.xml'
$stagedManifest = Join-Path $package 'AppxManifest.xml'
if ($Sparse) {
    Copy-Item -LiteralPath $manifestPath -Destination $stagedManifest -Force
} else {
    [xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw
    $manifest.Package.Identity.ProcessorArchitecture = @{ amd64 = 'x64'; arm64 = 'arm64' }[$Architecture]
    $properties = $manifest.Package.Properties
    $externalContent = $properties.GetElementsByTagName('AllowExternalContent', 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10')[0]
    [void]$properties.RemoveChild($externalContent)
    $manifest.Save($stagedManifest)
}
