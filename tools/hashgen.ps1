<#
.SYNOPSIS
    hashgen.ps1 —— 从样本目录生成 SHA256 哈希规则包（rules.hash.json）

.DESCRIPTION
    扫描指定目录里的样本文件，计算 SHA256，输出成规则文件片段，可直接放进规则目录由
    --rules-dir 热加载；也可以合并进已有的哈希包（-Merge）。

    产物只包含 meta + rules 两段，按 id 合并进主规则集，不影响其它规则。

.PARAMETER SampleDir
    样本目录（只读遍历，不修改任何文件）

.PARAMETER OutFile
    输出路径，默认 <脚本目录>\rules.hash.json

.PARAMETER Merge
    已存在同名输出文件时按 hash 合并，不重复添加

.EXAMPLE
    .\hashgen.ps1 -SampleDir D:\samples\cheats -OutFile E:\查挂小程序\rules\rules.hash.json

.EXAMPLE
    .\hashgen.ps1 -SampleDir D:\new-samples -Merge -Severity 5 -Confidence 0.95
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SampleDir,
    [string]$OutFile,
    [string[]]$Extensions = @('.exe', '.dll', '.sys', '.bat', '.ps1'),
    [int]$Severity = 5,
    [double]$Confidence = 0.95,
    [string]$IdPrefix = 'hash.known',
    [switch]$Merge,
    [long]$MaxSizeMB = 512
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $SampleDir)) { throw "样本目录不存在: $SampleDir" }

if ([string]::IsNullOrWhiteSpace($OutFile)) {
    $OutFile = Join-Path $PSScriptRoot 'rules.hash.json'
}

$OutFile = [System.IO.Path]::GetFullPath($OutFile)
$maxBytes = $MaxSizeMB * 1MB

Write-Host "样本目录: $SampleDir"
Write-Host "输出文件: $OutFile"

$existing = @{}
if ($Merge -and (Test-Path -LiteralPath $OutFile)) {
    try {
        $old = Get-Content -LiteralPath $OutFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($r in $old.rules) {
            if ($r.hash) { $existing[$r.hash.ToLower()] = $r }
        }
        Write-Host "已载入既有规则 $($existing.Count) 条（Merge 模式）"
    }
    catch {
        Write-Warning "既有规则文件解析失败，按新建处理: $($_.Exception.Message)"
    }
}

$rules = New-Object System.Collections.Generic.List[object]
$skipped = 0
$added = 0

Get-ChildItem -LiteralPath $SampleDir -Recurse -File | ForEach-Object {
    if ($Extensions -notcontains $_.Extension.ToLower()) { return }
    if ($_.Length -gt $maxBytes) { $skipped++; return }

    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
    if ($existing.ContainsKey($hash)) { return }

    $shortId = $hash.Substring(0, 12)
    $rules.Add([ordered]@{
        id          = "$IdPrefix.$shortId"
        type        = 'file_hash'
        pattern     = $hash
        hash        = $hash
        size        = $_.Length
        category    = 'file.suspect'
        severity    = $Severity
        confidence  = $Confidence
        enabled     = $true
        description = "已知样本: $($_.Name)（SHA256=$hash）"
        advice      = "命中的是完整文件哈希，仍建议人工确认文件来源与用途"
    })
    $added++
}

# 保留既有条目
foreach ($k in $existing.Keys) { $rules.Add($existing[$k]) }

$payload = [ordered]@{
    meta  = [ordered]@{
        name          = 'hash-pack'
        version       = (Get-Date -Format 'yyyy.MM.dd')
        updated       = (Get-Date -Format 'yyyy-MM-dd')
        schemaVersion = '2.0'
        description   = "由 hashgen.ps1 生成的哈希规则包（$($rules.Count) 条）"
    }
    rules = @($rules | Sort-Object { $_.id })
}

$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

$json = $payload | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "完成：新增 $added 条，跳过（超大）$skipped 个，总计 $($rules.Count) 条"
Write-Host "用法: EagleEye.exe scan --rules-dir <规则目录>"