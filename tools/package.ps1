<#
.SYNOPSIS
    package.ps1 —— 打包 Eagle Eye 可分发版本
.DESCRIPTION
    1) 发布自包含单文件（目标机无需 .NET）
    2) 组装 dist：exe + 全部规则 + 工具脚本 + 文档
    3) 打 zip（可直接作为 GitHub Release 附件）
.EXAMPLE
    .\package.ps1
    .\package.ps1 -SkipPublish
#>
[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [switch]$SkipPublish,
    [switch]$NoZip
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $repo 'src\EagleEye\EagleEye.csproj'
$publishDir = Join-Path $repo 'out\publish-portable'
$distName = "EagleEye-v$Version-win-x64"
$dist = Join-Path $repo "dist\$distName"

Write-Host "== 打包 $distName ==" -ForegroundColor Cyan

if (-not $SkipPublish) {
    $dotnet = if (Test-Path 'E:\dotnet8\dotnet.exe') { 'E:\dotnet8\dotnet.exe' } else { 'dotnet' }
    Write-Host "发布中（$dotnet）..."
    & $dotnet publish $proj -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true -p:Version=$Version -o $publishDir -v quiet
    if ($LASTEXITCODE -ne 0) { throw "发布失败" }
}

$exeSrc = Join-Path $publishDir 'EagleEye.exe'
if (-not (Test-Path $exeSrc)) { throw "找不到发布产物: $publishDir" }

if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Path $dist -Force | Out-Null

Copy-Item $exeSrc (Join-Path $dist 'EagleEye.exe') -Force
# 规则：直接从仓库组装（不依赖 publish 的复制行为，避免空目录）
$distRules = Join-Path $dist 'rules'
New-Item -ItemType Directory -Path $distRules -Force | Out-Null

$ruleSources = @(
    (Join-Path $repo 'rules\rules.json'),
    (Join-Path $repo 'rules\rules.delta-force.json'),
    (Join-Path $repo 'rules\rules.intel.json')
)

foreach ($src in $ruleSources) {
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $distRules (Split-Path $src -Leaf)) -Force
    } else {
        Write-Warning "缺少规则文件: $src"
    }
}

$ruleCount = (Get-ChildItem $distRules -Filter *.json).Count
if ($ruleCount -lt 2) { throw "规则组装不完整（只有 $ruleCount 个文件）" }
Write-Host "规则已组装: $ruleCount 个文件"

$toolsDir = Join-Path $dist 'tools'
New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
foreach ($f in @('audit-policy.ps1', 'hashgen.ps1', 'intel-to-rules.ps1', 'tune-thresholds.ps1', 'collect-game-info.ps1', 'package.ps1')) {
    $src = Join-Path $repo "tools\$f"
    if (Test-Path $src) { Copy-Item $src (Join-Path $toolsDir $f) -Force }
}

# 根目录放 README / LICENSE，docs 放详细文档
foreach ($f in @('README.md', 'README.en.md', 'LICENSE', 'CHANGELOG.md')) {
    $src = Join-Path $repo $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $dist $f) -Force }
}

$docsDir = Join-Path $dist 'docs'
New-Item -ItemType Directory -Path $docsDir -Force | Out-Null
$quick = Join-Path $repo 'docs\快速上手.txt'
if (Test-Path $quick) { Copy-Item $quick (Join-Path $docsDir '快速上手.txt') -Force }

$srcReadme = Join-Path $repo 'src\EagleEye\README.md'
if (Test-Path $srcReadme) { Copy-Item $srcReadme (Join-Path $docsDir '技术文档.md') -Force }

Get-ChildItem (Join-Path $repo 'docs') -Filter *.md -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $docsDir $_.Name) -Force }

Write-Host "校验打包结果..."
& (Join-Path $dist 'EagleEye.exe') validate 2>&1 | Select-String -Pattern '规则数量' | ForEach-Object { Write-Host $_.Line }

if (-not $NoZip) {
    $zip = Join-Path $repo "dist\$distName.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }

    # 刚校验过的 exe 可能还被短暂占用，重试打包
    $ok = $false
    for ($i = 1; $i -le 5; $i++) {
        try {
            Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zip -CompressionLevel Optimal -ErrorAction Stop
            $ok = $true
            break
        }
        catch {
            Start-Sleep -Milliseconds 800
        }
    }

    if ($ok) {
        Write-Host "已打包: $zip（$([math]::Round((Get-Item $zip).Length/1MB,1)) MB）"
    } else {
        Write-Warning "打包失败（文件被占用），稍后重跑：.\tools\package.ps1 -SkipPublish"
    }
}

Write-Host ""
Write-Host "分发目录: $dist" -ForegroundColor Green
Get-ChildItem $dist | ForEach-Object {
    if ($_.PSIsContainer) { Write-Host ("  {0,-24} <DIR>" -f $_.Name) }
    else { Write-Host ("  {0,-24} {1} MB" -f $_.Name, [math]::Round($_.Length/1MB,2)) }
}