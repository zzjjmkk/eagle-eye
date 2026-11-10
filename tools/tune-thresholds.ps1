<#
.SYNOPSIS
    tune-thresholds.ps1 —— 基于真实扫描报告做误报分析，产出可用的调参包

.DESCRIPTION
    读取一批扫描报告（JSON），按文件名前缀区分标签：
        clean-*.json  → 干净机器基线
        cheat-*.json  → 已确认作弊机器（可选；先有 clean 也能跑）

    输出：
        1) rules\tuning.suggested.json  —— 可被 --rules-dir 直接加载的覆盖包
        2) <ReportsDir>\tuning-report.md —— 人读的分析报告

    判定策略：
        · 只在干净机器命中、作弊样本 0 次 → 噪音
            - 命中面窄（≤ -WhitelistThreshold 个不同目标）→ 只加白，不动规则
            - 命中面宽且属受保护类型（句柄/驱动/哈希/特征码）→ 降权，不停用
            - 命中面宽且普通类型 → 停用（干净报告 ≥ -DisableAt）或降权
        · 干净/作弊都命中 → 规则保留；只把"干净出现、作弊从未出现"的目标加白
        · 规则集里不存在的 id（测试规则）→ 忽略

.PARAMETER ReportsDir
    报告目录，默认 <仓库>\out\reports

.EXAMPLE
    .\tune-thresholds.ps1 -ReportsDir ..\out\baseline -Label clean
#>
[CmdletBinding()]
param(
    [string]$ReportsDir,
    [string]$RulesFile,
    [string]$OutFile,
    [string]$Label = 'clean',
    [int]$DisableAt = 3,
    [double]$ConfidenceFactor = 0.6,
    [int]$MinRuleCount = 10,
    [int]$WhitelistThreshold = 20,
    [string[]]$ProtectTypes = @('handle_access', 'kernel_driver', 'file_hash', 'file_signature'),
    [switch]$NoWhitelist
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($ReportsDir)) { $ReportsDir = Join-Path $root 'out\reports' }
if ([string]::IsNullOrWhiteSpace($RulesFile))  { $RulesFile  = Join-Path $root 'src\EagleEye\rules\rules.json' }
if ([string]::IsNullOrWhiteSpace($OutFile))    { $OutFile    = Join-Path $root 'rules\tuning.suggested.json' }

$reports = Get-ChildItem -LiteralPath $ReportsDir -Filter *.json -File |
           Where-Object { $_.Name -notmatch 'tuning' } |
           Sort-Object Name

if ($reports.Count -eq 0) { throw "报告目录里没有 json: $ReportsDir" }

Write-Host "分析报告: $($reports.Count) 份（目录 $ReportsDir）"

$stats = @{}
$summary = New-Object System.Collections.Generic.List[object]

foreach ($file in $reports) {
    try {
        $r = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Write-Warning "跳过无法解析的报告: $($file.Name)"
        continue
    }

    $ruleCount = 0
    if ($r.ruleset -and $r.ruleset.ruleCount) { $ruleCount = [int]$r.ruleset.ruleCount }
    if ($ruleCount -lt $MinRuleCount) { continue }   # 跳过验证用的小规则包

    $isCheat = $file.Name -like 'cheat-*'
    # 注意：不能叫 $label —— PowerShell 变量名大小写不敏感，会覆盖参数 $Label
    $reportLabel = if ($isCheat) { 'cheat' } else { $Label }

    $summary.Add([pscustomobject]@{
        File  = $file.Name
        Label = $reportLabel
        Risk  = $r.summary.riskLevel
        Hits  = @($r.findings).Count
    })

    foreach ($f in @($r.findings)) {
        if (-not $f.ruleId) { continue }
        if (-not $stats.ContainsKey($f.ruleId)) {
            $stats[$f.ruleId] = [pscustomobject]@{
                RuleId = $f.ruleId
                Clean  = New-Object System.Collections.Generic.List[string]
                Cheat  = New-Object System.Collections.Generic.List[string]
                Scores = New-Object System.Collections.Generic.List[double]
                Types  = New-Object System.Collections.Generic.List[string]
            }
        }

        $entry = $stats[$f.ruleId]
        $targetName = if ($f.target) { [string]$f.target } else { '(unknown)' }
        if ($isCheat) { $entry.Cheat.Add($targetName) } else { $entry.Clean.Add($targetName) }
        $entry.Scores.Add([double]$f.score)
        if ($f.ruleType -and -not $entry.Types.Contains($f.ruleType)) { $entry.Types.Add($f.ruleType) }
    }
}

# 主规则集里的全部规则定义（按 id 索引）
$rulesDoc = Get-Content -LiteralPath $RulesFile -Raw -Encoding UTF8 | ConvertFrom-Json
$ruleById = @{}
foreach ($rule in @($rulesDoc.rules)) { $ruleById[$rule.id] = $rule }
foreach ($rule in @($rulesDoc.dma.rules)) { $ruleById[$rule.id] = $rule }
foreach ($rule in @($rulesDoc.vision.capture.moduleRules)) { if ($rule.id) { $ruleById[$rule.id] = $rule } }
foreach ($rule in @($rulesDoc.vision.hardware.rules)) { if ($rule.id) { $ruleById[$rule.id] = $rule } }
foreach ($rule in @($rulesDoc.deep.handles.rules)) { if ($rule.id) { $ruleById[$rule.id] = $rule } }
foreach ($rule in @($rulesDoc.deep.drivers.rules)) { if ($rule.id) { $ruleById[$rule.id] = $rule } }

$cleanReports = @($summary | Where-Object { $_.Label -ne 'cheat' }).Count
$cheatReports = @($summary | Where-Object { $_.Label -eq 'cheat' }).Count

$rows = New-Object System.Collections.Generic.List[object]
$tuningRules = New-Object System.Collections.Generic.List[object]
$whitelistProcesses = New-Object System.Collections.Generic.List[object]

foreach ($id in $stats.Keys) {
    $s = $stats[$id]
    $cleanTargets = @($s.Clean | Sort-Object -Unique)
    $cheatTargets = @($s.Cheat | Sort-Object -Unique)
    $cleanCount = $cleanTargets.Count
    $cheatCount = $cheatTargets.Count

    $isRealRule = $ruleById.ContainsKey($id)
    $noise = ($isRealRule -and $cleanCount -gt 0 -and $cheatCount -eq 0)
    $protected = ($s.Types | Where-Object { $ProtectTypes -contains $_ }).Count -gt 0

    $action = '保留'
    if ($noise) {
        if ($cleanCount -le $WhitelistThreshold) { $action = '仅加白' }
        elseif ($protected) { $action = '建议降权（受保护类型）' }
        elseif ($cleanCount -ge $DisableAt) { $action = '建议停用' }
        else { $action = '建议降权' }
    }

    $avgScore = 0
    if ($s.Scores.Count -gt 0) { $avgScore = [math]::Round(($s.Scores | Measure-Object -Average).Average, 1) }

    $rows.Add([pscustomobject]@{
        规则     = $id
        类型     = ($s.Types -join '/')
        干净命中 = $cleanCount
        作弊命中 = $cheatCount
        平均分   = $avgScore
        判定     = $action
    })

    # 需要动规则的：复制完整定义后调整
    if ($noise -and $action -ne '仅加白') {
        $base = $ruleById[$id]
        $copy = [ordered]@{}
        foreach ($prop in $base.PSObject.Properties) { $copy[$prop.Name] = $prop.Value }

        if (-not $copy.Contains('enabled')) { $copy['enabled'] = $true }
        if ($action -eq '建议停用') { $copy['enabled'] = $false }

        if ($copy.Contains('confidence')) {
            $copy['confidence'] = [math]::Round([double]$copy['confidence'] * $ConfidenceFactor, 3)
        }

        $oldDesc = if ($copy.Contains('description')) { $copy['description'] } else { '' }
        $copy['description'] = "调参：干净基线命中 $cleanCount 次、作弊样本 0 次 —— $oldDesc"
        $tuningRules.Add([pscustomobject]$copy)
    }

    # 目标级精准加白：干净出现过、作弊从未出现
    if ($isRealRule -and -not $NoWhitelist -and $cleanCount -gt 0) {
        $cleanOnly = @($cleanTargets | Where-Object { $cheatTargets -notcontains $_ })

        if ($cleanOnly.Count -le 50) {
            foreach ($targetName in $cleanOnly) {
                if ($targetName -match '^pid[0-9]+$') { continue }
                if ($targetName -notmatch '\.(exe|dll|sys)$') { continue }

                $whitelistProcesses.Add([ordered]@{
                    pattern       = $targetName
                    match         = 'exact'
                    reason        = "调参基线：$id 在干净机器命中、作弊样本从未出现"
                    suppressRules = @($id)
                })
            }
        }
    }
}

$ruleArray = $tuningRules.ToArray()
$whitelistArray = $whitelistProcesses.ToArray()

$pack = [ordered]@{
    meta = [ordered]@{
        name          = 'tuning-suggested'
        version       = (Get-Date -Format 'yyyy.MM.dd.HHmm')
        updated       = (Get-Date -Format 'yyyy-MM-dd')
        schemaVersion = '2.0'
        description   = "由 tune-thresholds.ps1 生成：基于 $cleanReports 份干净报告 / $cheatReports 份作弊报告"
    }
    rules     = $ruleArray
    whitelist = [ordered]@{
        processes = $whitelistArray
        paths     = [object[]]@()
        files     = [object[]]@()
        signers   = [object[]]@()
    }
}

$json = $pack | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
$rows | Sort-Object -Property 干净命中 -Descending | Format-Table -AutoSize

$reportPath = Join-Path $ReportsDir 'tuning-report.md'
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# 调参分析报告')
[void]$md.AppendLine('')
[void]$md.AppendLine("- 干净报告: $cleanReports 份")
[void]$md.AppendLine("- 作弊报告: $cheatReports 份")
[void]$md.AppendLine("- 调参包: $OutFile")
[void]$md.AppendLine('')
[void]$md.AppendLine('| 规则 | 类型 | 干净命中 | 作弊命中 | 平均分 | 判定 |')
[void]$md.AppendLine('|---|---|---|---|---|---|')
foreach ($row in ($rows | Sort-Object -Property 干净命中 -Descending)) {
    [void]$md.AppendLine("| $($row.规则) | $($row.类型) | $($row.干净命中) | $($row.作弊命中) | $($row.平均分) | $($row.判定) |")
}
[void]$md.AppendLine('')
[void]$md.AppendLine('## 下一步')
[void]$md.AppendLine('')
[void]$md.AppendLine('1. 把调参包放进规则目录，用 `--rules-dir` 重扫')
[void]$md.AppendLine('2. 对比 `summary.findings` 与 `summary.suppressedFindings`，确认噪音下降且真信号还在')
[void]$md.AppendLine('3. 补充 `cheat-*.json` 样本后再跑一次，防止把真信号降权掉')
[System.IO.File]::WriteAllText($reportPath, $md.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "调参包: $OutFile（规则 $($tuningRules.Count) 条，白名单 $($whitelistProcesses.Count) 条）"
Write-Host "分析报告: $reportPath"