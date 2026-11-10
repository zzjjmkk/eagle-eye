<#
.SYNOPSIS
    collect-game-info.ps1 —— 在跑着游戏的机器上采集真实基线

.DESCRIPTION
    网上的外挂名单既不可靠也不及时，最准的名单来自你自己的样本。
    这个脚本在游戏运行时跑一次，输出：
        · 游戏进程名 / 路径 / 命令行 / 签名 / 版本  → 用于填 rules 的 targetProcessPattern
        · 游戏进程已加载的模块（含签名状态）        → 用于发现异常模块
        · 本机现有进程里命中"外挂命名特征"的         → 用于人工确认误报

    它只读：不开进程内存、不注入、不 Hook、不截屏。

.EXAMPLE
    .\collect-game-info.ps1 -Pattern DeltaForce
#>
[CmdletBinding()]
param(
    [string]$Pattern = 'DeltaForce',
    [string]$OutFile,
    [int]$TopModules = 30
)

$ErrorActionPreference = 'Continue'

if ([string]::IsNullOrWhiteSpace($OutFile)) {
    $OutFile = Join-Path $PSScriptRoot 'game-info.json'
}

Write-Host "查找进程: *$Pattern*" -ForegroundColor Cyan

$procs = Get-Process | Where-Object {
    $_.ProcessName -like "*$Pattern*" -or
    ($_.Path -and $_.Path -like "*$Pattern*")
}

if (-not $procs) {
    Write-Warning "没找到匹配的进程。先启动游戏再跑，或用 -Pattern 换关键字（如 DeltaForceClient / Shipping）"
    return
}

$report = New-Object System.Collections.Generic.List[object]

foreach ($p in $procs) {
    $info = [ordered]@{
        name          = $p.ProcessName
        pid           = $p.Id
        path          = $null
        commandLine   = $null
        signature     = $null
        signer        = $null
        company       = $null
        version       = $null
        modules       = @()
    }

    try { $info.path = $p.Path } catch { }
    try { $info.company = $p.Company } catch { }
    try { $info.version = $p.ProductVersion } catch { }

    $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue
    if ($cim) { $info.commandLine = $cim.CommandLine }

    if ($info.path -and (Test-Path -LiteralPath $info.path)) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $info.path
            $info.signature = $sig.Status
            if ($sig.SignerCertificate) { $info.signer = $sig.SignerCertificate.Subject }
        } catch { }
    }

    $mods = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($m in ($p.Modules | Select-Object -First 400)) {
            $modSig = $null
            try {
                if ($m.FileName -and (Test-Path -LiteralPath $m.FileName)) {
                    $modSig = (Get-AuthenticodeSignature -LiteralPath $m.FileName).Status
                }
            } catch { }
            $mods.Add([ordered]@{ name = $m.ModuleName; path = $m.FileName; signature = $modSig })
        }
    } catch {
        Write-Warning "模块列表不可读（受保护进程）: $($p.ProcessName)"
    }
    $info.modules = $mods.ToArray()

    $report.Add([pscustomobject]$info)

    Write-Host ""
    Write-Host "== $($info.name) (PID $($info.pid)) ==" -ForegroundColor Green
    Write-Host "  路径   : $($info.path)"
    Write-Host "  命令行 : $($info.commandLine)"
    Write-Host "  签名   : $($info.signature)  $($info.signer)"
    Write-Host "  版本   : $($info.company) / $($info.version)"
    Write-Host "  模块   : $($mods.Count) 个"

    $unsigned = @($mods | Where-Object { $_.signature -and $_.signature -ne 'Valid' })
    if ($unsigned.Count -gt 0) {
        Write-Host "  未验签模块（前 10 个）:" -ForegroundColor Yellow
        $unsigned | Select-Object -First 10 | ForEach-Object { Write-Host "    - $($_.name)  [$($_.signature)]  $($_.path)" }
    }
}

# 反向：本机进程里像外挂的
Write-Host ""
Write-Host "== 本机进程里命中外挂命名特征的（可能是误报，用于调白名单）==" -ForegroundColor Cyan
$suspectKeywords = '辅助', '透视', '自瞄', '锁头', '穿墙', '方框', 'kmbox', 'aimbot', 'esp', 'cheat'
Get-Process | ForEach-Object {
    $n = $_.ProcessName
    foreach ($k in $suspectKeywords) {
        if ($n -like "*$k*") {
            $pathInfo = $null
            try { $pathInfo = $_.Path } catch { }
            Write-Host ("  {0,-28} {1}" -f $n, $pathInfo) -ForegroundColor Yellow
            break
        }
    }
}

$json = $report | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ""
Write-Host "已写入: $OutFile"
Write-Host ""
Write-Host "下一步：" -ForegroundColor Cyan
Write-Host "  1. 把上面打印的进程名填进 rules\rules.delta-force.json 的 whitelist（确认是游戏本体/官方组件）"
Write-Host "  2. 把异常模块名加进 df.module.* 规则"
Write-Host "  3. 把确认的外挂样本放进 samples\known-bad\delta-force\，跑 tools\hashgen.ps1 生成哈希包"