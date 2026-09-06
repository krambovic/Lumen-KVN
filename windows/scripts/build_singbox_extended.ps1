[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    # Latest extended release. 1.14 moved WireGuard outbounds to endpoints;
    # Lumen's runtime planner performs that migration before launch.
    [string]$Ref = "v1.14.0-extended-2.7.1",
    [string]$Repository = "https://github.com/shtorm-7/sing-box-extended.git",
    [string]$LumenRevision = "1",
    [string]$WorkDirectory = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$patchPath = Join-Path $repoRoot "patches\sing-box-extended-direct-masque.patch"
if (-not (Test-Path -LiteralPath $patchPath -PathType Leaf)) {
    throw "sing-box compatibility patch is missing: $patchPath"
}

$output = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $output
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$ownsWorkDirectory = [string]::IsNullOrWhiteSpace($WorkDirectory)
if ($ownsWorkDirectory) {
    $WorkDirectory = Join-Path ([IO.Path]::GetTempPath()) ("lumen-sing-box-" + [guid]::NewGuid().ToString("N"))
}
$workRoot = [IO.Path]::GetFullPath($WorkDirectory)
$source = Join-Path $workRoot "source"

try {
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
    & git clone --filter=blob:none --depth 1 --branch $Ref $Repository $source
    if ($LASTEXITCODE -ne 0) {
        throw "failed to clone sing-box-extended ref $Ref"
    }

    & git -C $source apply --unidiff-zero --check $patchPath
    if ($LASTEXITCODE -ne 0) {
        throw "the Lumen MASQUE patch is incompatible with sing-box-extended $Ref"
    }
    & git -C $source apply --unidiff-zero $patchPath
    if ($LASTEXITCODE -ne 0) {
        throw "failed to apply the Lumen MASQUE patch"
    }

    $tags = (Get-Content -LiteralPath (Join-Path $source "release\DEFAULT_BUILD_TAGS_WINDOWS") -Raw).Trim()
    $sharedLdflags = (Get-Content -LiteralPath (Join-Path $source "release\LDFLAGS") -Raw).Trim()
    $upstreamVersion = $Ref.TrimStart([char]'v')
    $version = "$upstreamVersion-lumen.$LumenRevision"
    $ldflags = "-X github.com/sagernet/sing-box/constant.Version=$version $sharedLdflags -s -w -buildid="

    $env:CGO_ENABLED = "0"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    Push-Location $source
    try {
        & go build -trimpath -o $output -tags $tags -ldflags $ldflags ./cmd/sing-box
        if ($LASTEXITCODE -ne 0) {
            throw "failed to build sing-box-extended"
        }
    }
    finally {
        Pop-Location
    }

    & $output version
    if ($LASTEXITCODE -ne 0) {
        throw "built sing-box executable did not start"
    }

    # NaiveProxy on Windows loads Cronet dynamically.  The extended project's
    # regular archive does not contain the DLL, while its matching purego
    # archive does.  Fetch the companion from the exact same release and keep
    # it beside the Lumen-patched executable for installer and portable builds.
    $headers = @{ "User-Agent" = "Lumen-build" }
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
        $headers["Authorization"] = "Bearer $env:GITHUB_TOKEN"
    }
    $releaseApi = "https://api.github.com/repos/shtorm-7/sing-box-extended/releases/tags/$Ref"
    $release = Invoke-RestMethod $releaseApi -Headers $headers
    $cronetAsset = $release.assets |
        Where-Object { $_.name -like "*-windows-amd64-purego.zip" } |
        Select-Object -First 1
    if (-not $cronetAsset) {
        throw "matching sing-box extended archive with libcronet.dll was not found"
    }
    $cronetArchive = Join-Path $workRoot "sing-box-cronet.zip"
    $cronetExtract = Join-Path $workRoot "cronet"
    Invoke-WebRequest $cronetAsset.browser_download_url -OutFile $cronetArchive -Headers $headers
    $publishedDigest = [string]$cronetAsset.digest
    if ($publishedDigest -notmatch '^sha256:([0-9a-fA-F]{64})$') {
        throw "the libcronet archive does not provide a published SHA-256"
    }
    $actualDigest = (Get-FileHash -LiteralPath $cronetArchive -Algorithm SHA256).Hash
    if ($actualDigest -ne $Matches[1]) {
        throw "the libcronet archive SHA-256 does not match"
    }
    Expand-Archive $cronetArchive -DestinationPath $cronetExtract -Force
    $cronet = Get-ChildItem $cronetExtract -Recurse -Filter libcronet.dll -File |
        Select-Object -First 1
    if (-not $cronet -or $cronet.Length -lt 1024) {
        throw "libcronet.dll is missing or damaged in the sing-box archive"
    }
    Copy-Item -LiteralPath $cronet.FullName -Destination (Join-Path $outputDirectory "libcronet.dll") -Force
}
finally {
    if ($ownsWorkDirectory -and (Test-Path -LiteralPath $workRoot)) {
        $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if ($workRoot.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
