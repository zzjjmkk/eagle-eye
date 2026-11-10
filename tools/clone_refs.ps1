# 浅克隆开源参考项目到 13_开源参考\github\
$dest = Join-Path $PSScriptRoot "..\13_开源参考\github"
New-Item -ItemType Directory -Path $dest -Force | Out-Null

$repos = @(
  "hasherezade/pe-sieve",
  "hasherezade/hollows_hunter",
  "forrest-orr/moneta",
  "forrest-orr/artifacts-kit",
  "LordNoteworthy/al-khaser",
  "a0rtega/pafish",
  "winsiderss/systeminformer",
  "ufrisk/MemProcFS",
  "ufrisk/pcileech",
  "erocarrera/pefile",
  "horsicq/Detect-It-Easy",
  "microsoft/Windows-driver-samples",
  "microsoft/krabsetw",
  "jdu2600/Windows10EtwEvents",
  "redcanaryco/atomic-red-team",
  "codestage/Actk"
)

foreach ($r in $repos) {
  $name = $r.Split("/")[1]
  $target = Join-Path $dest $name
  if (Test-Path $target) { Write-Host "[skip] $name"; continue }
  Write-Host "[clone] $r"
  git clone --depth 1 "https://github.com/$r.git" $target 2>&1 | Out-String | Write-Host
}
Write-Host "完成，路径: $dest"