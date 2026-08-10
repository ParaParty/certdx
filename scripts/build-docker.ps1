$ErrorActionPreference = "Stop"

$repoRoot = (git rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to find the Git repository root."
}

$gitCommit = (git -C $repoRoot rev-parse --short=8 HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read the Git commit."
}

$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$image = "paraparty/certdx-tools:$gitCommit"

docker build `
    --build-arg "VERSION=$gitCommit" `
    --build-arg "BUILD_DATE=$buildDate" `
    --tag $image `
    $repoRoot

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Built $image"
