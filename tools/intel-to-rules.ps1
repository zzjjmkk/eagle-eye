<#
.SYNOPSIS
    intel-to-rules.ps1 —— 把人工整理的情报（关键词 / 网页文本）转成可用规则

.DESCRIPTION
    卡密平台、论坛曝光帖、客服工单里拿到的东西，本质是"字符串"。
    这个脚本把字符串批量转成 process_name / module_name / file_name 三类规则，
    并自动去重、标注置信度、生成复核清单。

    三种输入模式：
        list    —— 每行一个关键词（最常用）
        csv     —— 结构化：type,pattern,severity,confidence,description
        extract —— 给一段网页/聊天文本，自动抽取候选词（只出候选，不直接生成规则）

    输出：
        rules\rules.intel.json   —— 规则包，可 --rules-dir 直接加载
        <Input>\intel-review.md  —— 复核清单（哪些词会变成规则、预期误报面）

.EXAMPLE
    .\intel-to-rules.ps1 -InputFile rules\intel\delta-force-candidates.txt -Mode list

.EXAMPLE
    .\intel-to-rules.ps1 -InputFile page.txt -Mode extract -OutCandidates rules\intel\new-candidates.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [string]$OutFile,
    [ValidateSet('list', 'csv', 'extract')][string]$Mode = 'list',
    [string]$OutCandidates,
    [int]$Severity = 3,
    [double]$Confidence = 0.4,
    [string]$Category = 'intel',
    [string]$IdPrefix = 'intel',
    [int]$MinTokenLength = 2,
    [string]$RulesFile
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($OutFile))   { $OutFile   = Join-Path $root 'rules\rules.intel.json' }
if ([string]::IsNullOrWhiteSpace($RulesFile)) { $RulesFile = Join-Path $root 'src\EagleEye\rules\rules.json' }

if (-not (Test-Path -LiteralPath $InputFile)) { throw "输入文件不存在: $InputFile" }

$text = Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8

# ---------- extract 模式：只抽候选，不生成规则 ----------
if ($Mode -eq 'extract') {
    if ([string]::IsNullOrWhiteSpace($OutCandidates)) {
        $OutCandidates = Join-Path (Split-Path -Parent $InputFile) 'new-candidates.txt'
    }

    $stop = @('the','and','for','with','this','that','from','http','https','www','com','net','org',
              '支持','我们','可以','如何','什么','这个','那个','因为','所以','但是','如果','已经',
              '三角洲行动','游戏','下载','官网','版本','更新','用户','登录','注册')

    $tokens = New-Object System.Collections.Generic.List[string]

    foreach ($m in [regex]::Matches($text, '[\u4e00-\u9fa5]{2,8}')) {
        $w = $m.Value
        if ($stop -contains $w) { continue }
        if ($w.Length -lt $MinTokenLength) { continue }
        if (-not $tokens.Contains($w)) { $tokens.Add($w) }
    }
    foreach ($m in [regex]::Matches($text, '[A-Za-z][A-Za-z0-9_\-]{2,20}')) {
        $w = $m.Value
        if ($stop -contains $w.ToLower()) { continue }
        if (-not $tokens.Contains($w)) { $tokens.Add($w) }
    }

    [System.IO.File]::WriteAllLines($OutCandidates, $tokens, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "抽出候选词 $($tokens.Count) 个 → $OutCandidates"
    Write-Host "人工筛掉通用词后，用 -Mode list -InputFile $OutCandidates 生成规则"
    return
}

# ---------- 读取输入 ----------
$entries = New-Object System.Collections.Generic.List[object]

if ($Mode -eq 'csv') {
    $rows = $text -split "`r?`n" | Where-Object { $_.Trim() -ne '' -and -not $_.StartsWith('#') }
    $header = $rows[0] -split ','
    for ($i = 1; $i -lt $rows.Count; $i++) {
        $cells = $rows[$i] -split ','
        if ($cells.Count -lt 2) { continue }
        $entries.Add([pscustomobject]@{
            Type        = $cells[0].Trim()
            Pattern     = $cells[1].Trim()
            Severity    = if ($cells.Count -gt 2 -and $cells[2]) { [int]$cells[2] } else { $Severity }
            Confidence  = if ($cells.Count -gt 3 -and $cells[3]) { [double]$cells[3] } else { $Confidence }
            Description = if ($cells.Count -gt 4) { $cells[4].Trim() } else { '' }
        })
    }
}
else {
    foreach ($line in ($text -split "`r?`n")) {
        $w = $line.Trim()
        if ($w -eq '' -or $w.StartsWith('#')) { continue }
        $entries.Add([pscustomobject]@{
            Type        = 'auto'
            Pattern     = $w
            Severity    = $Severity
            Confidence  = $Confidence
            Description = "情报导入：$w"
        })
    }
}

if ($entries.Count -eq 0) { throw "输入里没有有效条目: $InputFile" }

# ---------- 已有规则 id（用于去重）----------
$existingIds = @{}
if (Test-Path -LiteralPath $RulesFile) {
    $doc = Get-Content -LiteralPath $RulesFile -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($r in @($doc.rules)) { $existingIds[$r.id] = $true }
}

# ---------- 生成规则 ----------
$rules = New-Object System.Collections.Generic.List[object]
$review = New-Object System.Collections.Generic.List[object]
$added = 0
$skipped = 0

function New-Id([string]$prefix, [string]$type, [string]$pattern) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$type|$pattern")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash($bytes)
    $hex = -join ($hash[0..3] | ForEach-Object { $_.ToString('x2') })
    return "$prefix.$type.$hex"
}

function Add-Rule([string]$type, [string]$pattern, [int]$sev, [double]$conf, [string]$desc) {
    $id = New-Id $IdPrefix $type $pattern
    if ($existingIds.ContainsKey($id)) { $script:skipped++; return }

    $glob = if ($pattern -match '[\*\?]') { $pattern } else { "*$pattern*" }

    $rules.Add([ordered]@{
        id          = $id
        type        = $type
        pattern     = $glob
        match       = 'glob'
        category    = $Category
        severity    = $sev
        confidence  = $conf
        description = $desc
        enabled     = $true
    })

    $existingIds[$id] = $true
    $script:added++
    $review.Add([pscustomobject]@{ 规则ID = $id; 类型 = $type; 模式 = $glob; 等级 = $sev; 置信度 = $conf })
}

foreach ($e in $entries) {
    $p = $e.Pattern.Trim()
    if ($p -eq '') { continue }

    switch ($e.Type.ToLower()) {
        'process' { Add-Rule 'process_name' $p $e.Severity $e.Confidence $e.Description }
        'module'  { Add-Rule 'module_name'  $p $e.Severity $e.Confidence $e.Description }
        'file'    { Add-Rule 'file_name'    $p $e.Severity $e.Confidence $e.Description }
        default {
            Add-Rule 'process_name' $p $e.Severity $e.Confidence $e.Description
            Add-Rule 'module_name'  $p $e.Severity $e.Confidence $e.Description
            Add-Rule 'file_name'    $p $e.Severity $e.Confidence $e.Description
        }
    }
}

# ---------- 输出 ----------
$ruleArray = $rules.ToArray()

$pack = [ordered]@{
    meta = [ordered]@{
        name          = 'intel-pack'
        version       = (Get-Date -Format 'yyyy.MM.dd.HHmm')
        updated       = (Get-Date -Format 'yyyy-MM-dd')
        schemaVersion = '2.0'
        description   = "由 intel-to-rules.ps1 从 $([System.IO.Path]::GetFileName($InputFile)) 生成（$Mode 模式）"
    }
    rules = $ruleArray
}

$json = $pack | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))

$reviewPath = Join-Path (Split-Path -Parent $InputFile) 'intel-review.md'
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# 情报转规则 复核清单')
[void]$md.AppendLine('')
[void]$md.AppendLine("- 输入: $InputFile")
[void]$md.AppendLine("- 模式: $Mode")
[void]$md.AppendLine("- 生成: $added 条")
[void]$md.AppendLine('')
[void]$md.AppendLine('| 规则ID | 类型 | 模式 | 等级 | 置信度 |')
[void]$md.AppendLine('|---|---|---|---|---|')
foreach ($r in $review) {
    [void]$md.AppendLine("| $($r.规则ID) | $($r.类型) | ``$($r.模式)`` | $($r.等级) | $($r.置信度) |")
}
[void]$md.AppendLine('')
[void]$md.AppendLine('## 复核要点')
[void]$md.AppendLine('')
[void]$md.AppendLine('1. 这些是**命名类弱信号**，误报率高，severity 默认只给 3')
[void]$md.AppendLine('2. 越短的关键词误报越大（如 `辅助`），建议连品牌名一起写（如 `XX辅助`）')
[void]$md.AppendLine('3. 确认无误后把 `rules.intel.json` 放进规则目录，`--rules-dir` 会自动合并')
[void]$md.AppendLine('4. 命中后跑 `tune-thresholds.ps1` 复测误报')
[System.IO.File]::WriteAllText($reviewPath, $md.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
$review | Format-Table -AutoSize
Write-Host "规则包: $OutFile（新增 $added 条，跳过重复 $skipped 条）"
Write-Host "复核清单: $reviewPath"