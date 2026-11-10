#requires -Version 5.1
<#
    audit-policy.ps1 —— 合规红线自检
    逐条验证：代码里不存在注入/内存读写/Hook/驱动隐藏/反反作弊/绕过反作弊/
              伪造签名/提权/关闭 HVCI/修改游戏文件 的实现，且规则与报告满足
              「可解释、可审计、可白名单抑制」。

    实现说明：匹配前会剥离 C# 与 C 的注释，避免注释里写"绝不使用 XXX"造成误报。

    退出码：0 = 全部通过；1 = 存在违规
#>

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$srcDir = Join-Path $root 'src\EagleEye'
$drvDir = Join-Path $root 'native\pciecfg'
$rulesFile = Join-Path $root 'rules\rules.json'

$violations = New-Object System.Collections.Generic.List[string]
$checks = New-Object System.Collections.Generic.List[object]

function Add-Check($name, $ok, $detail) {
    $checks.Add([pscustomobject]@{ 检查项 = $name; 结果 = $(if ($ok) { 'PASS' } else { 'FAIL' }); 说明 = $detail })
    if (-not $ok) { $violations.Add("$name => $detail") }
}

function Get-CodeOnly([string]$path) {
    $text = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    $code = [regex]::Replace($text, '/\*[\s\S]*?\*/', '')
    $code = [regex]::Replace($code, '//[^\r\n]*', '')
    return $code
}

# ------------------------------------------------------------------
# 1. C# 代码红线（Kernel 目录是授权的一次性驱动装载，单独评估）
# ------------------------------------------------------------------
$bannedCs = [ordered]@{
    'WriteProcessMemory'  = '进程内存写入'
    'ReadProcessMemory'   = '进程内存读取'
    'VirtualAllocEx'      = '远程内存分配'
    'VirtualProtectEx'    = '远程内存属性修改'
    'CreateRemoteThread'  = '远程线程注入'
    'NtCreateThreadEx'    = '远程线程创建'
    'RtlCreateUserThread' = '远程线程创建'
    'SetWindowsHookEx'    = 'API Hook'
    'NtMapViewOfSection'  = '跨进程映射'
    'QueueUserAPC'        = 'APC 注入'
    'SetWinEventHook'     = 'WinEvent Hook'
}

$csFiles = Get-ChildItem $srcDir -Recurse -Filter *.cs | Where-Object { $_.FullName -notmatch '\\(bin|obj|Kernel)\\' }
$bannedHits = @()
foreach ($f in $csFiles) {
    $code = Get-CodeOnly $f.FullName
    foreach ($name in $bannedCs.Keys) {
        if ($code -match [regex]::Escape($name)) { $bannedHits += "$name($($bannedCs[$name])) in $($f.Name)" }
    }
}
Add-Check 'C# 无注入/内存读写/Hook 实现' ($bannedHits.Count -eq 0) $(if ($bannedHits.Count -eq 0) { "扫描 $($csFiles.Count) 个文件（已剥离注释），0 处命中" } else { $bannedHits -join '; ' })

$bannedThemes = 'BypassAntiCheat|DisableVanguard|BattlEyeBypass|EACBypass|SeDebugPrivilege|AdjustTokenPrivileges|bcdedit|testsigning'
$themeHits = @()
foreach ($f in $csFiles) {
    $code = Get-CodeOnly $f.FullName
    if ($code -match $bannedThemes) { $themeHits += $f.Name }
}
Add-Check 'C# 无反反作弊/绕过/提权/关 HVCI' ($themeHits.Count -eq 0) $(if ($themeHits.Count -eq 0) { '0 处命中' } else { $themeHits -join ', ' })

# ------------------------------------------------------------------
# 2. 驱动源码红线
# ------------------------------------------------------------------
$drvFile = Join-Path $drvDir 'PcieCfg.c'
$drvCode = Get-CodeOnly $drvFile

$bannedDrv = [ordered]@{
    'IRP_MN_WRITE_CONFIG'             = '写 PCIe 配置空间'
    'MmCopyVirtualMemory'             = '跨进程内存读写'
    'MmMapIoSpace'                    = '物理内存映射'
    'MmGetPhysicalAddress'            = '物理地址获取'
    'PsLookupProcessByProcessId'      = '进程对象查询'
    'KeStackAttachProcess'            = '进程上下文附加'
    'ObRegisterCallbacks'             = '句柄回调拦截'
    'ZwCreateFile'                    = '文件操作'
    'ZwOpenProcess'                   = '进程句柄操作'
    'PsSetCreateProcessNotifyRoutine' = '进程通知回调'
}
$drvHits = @()
foreach ($name in $bannedDrv.Keys) {
    if ($drvCode -match [regex]::Escape($name)) { $drvHits += "$name($($bannedDrv[$name]))" }
}
Add-Check '驱动无写配置空间/内存读写/回调/文件操作' ($drvHits.Count -eq 0) $(if ($drvHits.Count -eq 0) { '仅使用 IRP_MN_READ_CONFIG' } else { $drvHits -join '; ' })

Add-Check '驱动只发 READ_CONFIG' ($drvCode -match 'IRP_MN_READ_CONFIG') '代码中存在 IRP_MN_READ_CONFIG 的 IRP 构造'

$infText = Get-Content -LiteralPath (Join-Path $drvDir 'PcieCfg.inf') -Raw -Encoding UTF8
Add-Check '驱动服务为按需启动（StartType=3）' ($infText -match 'StartType=3') 'StartType=3 表示 SERVICE_DEMAND_START，不会自启'

# ------------------------------------------------------------------
# 3. 驱动装载代码：只允许在 Kernel 目录出现
# ------------------------------------------------------------------
$createServiceOutside = @()
foreach ($f in $csFiles) {
    if ((Get-CodeOnly $f.FullName) -match 'CreateService') { $createServiceOutside += $f.Name }
}
Add-Check 'CreateService 仅存在于 Kernel 装载模块' ($createServiceOutside.Count -eq 0) $(if ($createServiceOutside.Count -eq 0) { '其他模块不含服务创建代码' } else { $createServiceOutside -join ', ' })

# ------------------------------------------------------------------
# 4. 规则可解释性
# ------------------------------------------------------------------
$rules = Get-Content -LiteralPath $rulesFile -Raw -Encoding UTF8 | ConvertFrom-Json
$noDesc = @($rules.rules | Where-Object { -not $_.description })
$noDmaDesc = @($rules.dma.rules | Where-Object { -not $_.description })
Add-Check '规则均有 description（可解释）' ($noDesc.Count -eq 0 -and $noDmaDesc.Count -eq 0) "通用 $($rules.rules.Count) 条 / DMA $($rules.dma.rules.Count) 条，缺失 $($noDesc.Count + $noDmaDesc.Count) 条"
$noCat = @($rules.rules | Where-Object { -not $_.category })
Add-Check '规则均有 category（可分类统计）' ($noCat.Count -eq 0) "缺失 $($noCat.Count) 条"
Add-Check '规则集有版本号与更新时间' ($rules.meta.version -and $rules.meta.updated) "version=$($rules.meta.version), updated=$($rules.meta.updated)"

# ------------------------------------------------------------------
# 5. 白名单可抑制
# ------------------------------------------------------------------
$suppressSupported = (Get-Content -LiteralPath (Join-Path $srcDir 'Models\Rule.cs') -Raw -Encoding UTF8) -match 'SuppressRules'
Add-Check '白名单段存在' ($null -ne $rules.whitelist) "processes=$($rules.whitelist.processes.Count) paths=$($rules.whitelist.paths.Count) files=$($rules.whitelist.files.Count) signers=$($rules.whitelist.signers.Count)"
Add-Check '支持定向抑制 suppressRules' $suppressSupported 'WhitelistEntry.SuppressRules 字段存在'

# ------------------------------------------------------------------
# 6. 报告可审计性
# ------------------------------------------------------------------
$latest = Get-ChildItem (Join-Path $root 'out\reports') -Filter '*.json' -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -notmatch '^aggregate' -and $_.DirectoryName -notmatch 'aggregates' } |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latest) {
    $report = Get-Content -LiteralPath $latest.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $badEvidence = @($report.findings | Where-Object { -not $_.ruleId -or -not $_.evidence })
    $auditOk = ($report.audit -and $report.audit.networkUsed -eq $false)
    Add-Check '报告命中均带 ruleId + evidence' ($badEvidence.Count -eq 0) "检查 $($report.findings.Count) 条，缺证据 $($badEvidence.Count) 条（来源 $($latest.Name)）"
    Add-Check '报告含审计段且无网络访问' $auditOk "processOpen=$($report.audit.processOpenAttempts) networkUsed=$($report.audit.networkUsed)"
} else {
    Add-Check '报告可审计性' $false '未找到任何报告 JSON'
}

# ------------------------------------------------------------------
# 7. 视觉模块（AI Vision）：不装钩子、不注册原始输入、不截屏
# ------------------------------------------------------------------
$visionFiles = Get-ChildItem $srcDir -Recurse -Filter *.cs | Where-Object { $_.Name -match 'Vision|InputBehavior|WindowApi' }
$visionBanned = 'SetWindowsHookEx|RegisterRawInputDevices|BitBlt|CreateCompatibleDC|CopyFromScreen|PrintWindow|GraphicsCaptureItem'
$visionHits = @()
foreach ($f in $visionFiles) {
    if ((Get-CodeOnly $f.FullName) -match $visionBanned) { $visionHits += $f.Name }
}
Add-Check '视觉模块无 Hook/RawInput/截屏 API' ($visionHits.Count -eq 0) $(if ($visionHits.Count -eq 0) { "扫描 $($visionFiles.Count) 个文件，0 处命中（行为统计用 GetCursorPos 轮询）" } else { $visionHits -join ', ' })

$visionAll = @($rules.vision.capture.moduleRules) + @($rules.vision.hardware.rules)
$badVision = @($visionAll | Where-Object { $_.confidence -gt 0.7 -or $_.severity -gt 4 })
Add-Check '视觉规则 confidence<=0.7 / severity<=4' ($badVision.Count -eq 0) "共 $($visionAll.Count) 条，越界 $($badVision.Count) 条"
Add-Check '视觉判定上限不高于「可疑」' ($rules.vision.aggregation.maxLevel -ne '高度可疑') "maxLevel=$($rules.vision.aggregation.maxLevel)"

# ------------------------------------------------------------------
# 输出
# ------------------------------------------------------------------

# ------------------------------------------------------------------
# 9. 深度扫描模块：句柄/驱动/overlay/特征码，全部只读
# ------------------------------------------------------------------
$deepFiles = Get-ChildItem $srcDir -Recurse -Filter *.cs |
    Where-Object { $_.Name -match 'Handle|Driver|Overlay|FileSignature|ExtendedScans' }
$deepBanned = 'ReadProcessMemory|WriteProcessMemory|VirtualQueryEx|SetWindowLong|SendMessage|PostMessage|BitBlt|CopyFromScreen|SeDebugPrivilege|AdjustTokenPrivileges|NtSetInformation'
$deepHits = @()
foreach ($f in $deepFiles) {
    if ((Get-CodeOnly $f.FullName) -match $deepBanned) { $deepHits += $f.Name }
}
Add-Check '深度扫描无内存读写/窗口改写/提权' ($deepHits.Count -eq 0) $(if ($deepHits.Count -eq 0) { "扫描 $($deepFiles.Count) 个文件，0 处命中" } else { $deepHits -join ', ' })

$handleIoctl = (Get-CodeOnly (Join-Path $srcDir 'Native\HandleInterop.cs'))
Add-Check '句柄线索仅用 DuplicateHandle 读 PID' (($handleIoctl -match 'DuplicateHandle') -and ($handleIoctl -notmatch 'ReadProcessMemory')) '不读取目标进程内存'
$checks | Format-Table -AutoSize -Wrap

if ($violations.Count -gt 0) {
    Write-Host ""
    Write-Host "红线自检未通过：" -ForegroundColor Red
    $violations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host ""
Write-Host "红线自检全部通过（$($checks.Count) 项）。" -ForegroundColor Green
exit 0