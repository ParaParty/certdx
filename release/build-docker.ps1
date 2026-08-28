param(
    [switch]$Dev
)

$ErrorActionPreference = "Stop"

$repoRoot = (git rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to find the Git repository root."
}

$gitCommit = (git -C $repoRoot rev-parse --short=8 HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read the Git commit."
}

$devArg = if ($Dev) { "1" } else { "0" }
$image = if ($Dev) { "paraparty/certdx:$gitCommit-dev" } else { "paraparty/certdx:$gitCommit" }

docker build `
    --build-arg "DEV=$devArg" `
    --tag $image `
    $repoRoot

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Built $image"
