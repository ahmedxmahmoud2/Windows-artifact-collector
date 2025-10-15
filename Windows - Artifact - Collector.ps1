<#
Forensic_Analyzer_Collector.ps1
All-in-one collector + initial analysis (PowerShell only).
No external tools required for basic parsing.
Run as Administrator.
#>

param(
    [int]$LookbackDays = 30,
    [switch]$HashAll
)

# -------------------- Setup & helpers --------------------
function Log-Info { param($m) $t=(Get-Date).ToString('s'); "$t`t[INFO] $m" | Tee-Object -FilePath $global:LogFile -Append; Write-Host $m -ForegroundColor Cyan }
function Log-Warn { param($m) $t=(Get-Date).ToString('s'); "$t`t[WARN] $m" | Tee-Object -FilePath $global:LogFile -Append; Write-Host $m -ForegroundColor Yellow }
function Log-Err  { param($m) $t=(Get-Date).ToString('s'); "$t`t[ERROR] $m" | Tee-Object -FilePath $global:LogFile -Append; Write-Host $m -ForegroundColor Red }

# Ensure script is run as a file
$scriptFolder = $PSScriptRoot
if (-not $scriptFolder) { $scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path }
$toolsPath = Join-Path $scriptFolder "tools"

# Require admin
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires Administrator privileges. Re-run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

# Output root on Desktop using environment variable
$desktop = [Environment]::GetFolderPath("Desktop")
$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$HostName = $env:COMPUTERNAME
$OutRoot = Join-Path $desktop "Forensic_Artifacts_$ts"
New-Item -Path $OutRoot -ItemType Directory -Force | Out-Null

$global:LogFile = Join-Path $OutRoot "collector.log"
"=== Forensic Analyzer Collector started: $((Get-Date).ToString('o')) ===" | Out-File -FilePath $global:LogFile -Encoding utf8
Log-Info "Output root: $OutRoot"
Log-Info "LookbackDays: $LookbackDays ; HashAll: $($HashAll.IsPresent)"
Log-Info "Tools folder: $toolsPath (PECmd/AmcacheParser/sqlite3 optional)"

# Make subfolders
$RegOut      = Join-Path $OutRoot "Registry";       New-Item -Path $RegOut -ItemType Directory -Force | Out-Null
$LogsOut     = Join-Path $OutRoot "Logs";           New-Item -Path $LogsOut -ItemType Directory -Force | Out-Null
$ParsedOut   = Join-Path $OutRoot "Parsed";         New-Item -Path $ParsedOut -ItemType Directory -Force | Out-Null
$NetOut      = Join-Path $OutRoot "Network";        New-Item -Path $NetOut -ItemType Directory -Force | Out-Null
$SysOut      = Join-Path $OutRoot "SystemInfo";     New-Item -Path $SysOut -ItemType Directory -Force | Out-Null
$PersistOut  = Join-Path $OutRoot "Persistence";    New-Item -Path $PersistOut -ItemType Directory -Force | Out-Null
$BrowserOut  = Join-Path $OutRoot "Browsers";       New-Item -Path $BrowserOut -ItemType Directory -Force | Out-Null
$OtherOut    = Join-Path $OutRoot "OtherArtifacts"; New-Item -Path $OtherOut -ItemType Directory -Force | Out-Null
$AnalysisOut = Join-Path $OutRoot "Analysis";       New-Item -Path $AnalysisOut -ItemType Directory -Force | Out-Null

# -------------------- Registry export & hives --------------------
Log-Info "Collecting registry keys and system hives."
Write-Progress -Activity "Collecting Registry" -Status "Starting" -PercentComplete 0
$regKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
)
function Export-RegKeySafe($key) {
    try {
        $safe = ($key -replace '[:\\\/]','_' -replace '\s+','')
        $txt = Join-Path $RegOut ("reg_$safe.txt")
        $obj = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($obj) { $obj | Out-String | Set-Content -Path $txt -Encoding utf8; Log-Info "Exported $key -> $(Split-Path $txt -Leaf)" } else { Log-Warn "No data/inaccessible: $key" }
        $parts = $key -split ":\\"; if ($parts.Count -ge 2) { $root=$parts[0]; $sub=$parts[1]; $regf = Join-Path $RegOut ("regexp_$safe.reg"); try { cmd.exe /c "reg export `"$root\$sub`" `"$regf`" /y" | Out-Null; if (Test-Path $regf) { Log-Info "reg exported $root\$sub -> $(Split-Path $regf -Leaf)" } } catch { Log-Warn "reg export failed for $key" } }
    } catch { Log-Err "Export-RegKeySafe $key failed: $_" }
}
$totalReg = $regKeys.Count; $i = 0
foreach ($k in $regKeys) {
    $i++
    Write-Progress -Activity "Exporting Registry Keys" -Status "Processing $k" -PercentComplete ($i / $totalReg * 100)
    Export-RegKeySafe -key $k
}

# System hives
$systemHiveMap = @{ "HKLM\SYSTEM"="SYSTEM.save"; "HKLM\SOFTWARE"="SOFTWARE.save"; "HKLM\SAM"="SAM.save"; "HKLM\SECURITY"="SECURITY.save" }
$hiveFolder = Join-Path $RegOut "hives"; New-Item -Path $hiveFolder -ItemType Directory -Force | Out-Null
$failedHives = @()
$i = 0
foreach ($h in $systemHiveMap.Keys) {
    $i++
    Write-Progress -Activity "Saving System Hives" -Status "Processing $h" -PercentComplete ($i / $systemHiveMap.Count * 100)
    $dst = Join-Path $hiveFolder $systemHiveMap[$h]
    try { Log-Info "reg save $h -> $dst"; cmd.exe /c "reg save `"$h`" `"$dst`" /y" | Out-Null; Start-Sleep -Milliseconds 200
        if (Test-Path $dst) { $hsh = (Get-FileHash -Path $dst -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash; Log-Info "Saved $h -> $(Split-Path $dst -Leaf) (sha256:$($hsh.Substring(0,16)))" } else { Log-Warn "reg save produced no file for $h"; $failedHives += $h } } catch { Log-Err "reg save failed ${h}: $_"; $failedHives += $h }
}

# HKU saves
try {
    $hku = Get-ChildItem HKU: -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("S-1-5-18","S-1-5-19","S-1-5-20") }
    foreach ($entry in $hku) {
        $sid = $entry.PSChildName; $dst = Join-Path $hiveFolder ("HKU_$sid.save")
        try { cmd.exe /c "reg save `\"HKU\$sid`\" `"$dst`" /y" | Out-Null; if (Test-Path $dst) { Log-Info "Saved HKU\$sid -> $(Split-Path $dst -Leaf)" } else { Log-Warn "HKU\$sid reg save produced no file" } } catch { Log-Warn "Failed reg save HKU\$sid : $_" }
    }
} catch { Log-Warn "Enumerate HKU failed: $_" }

# VSS fallback
if ($failedHives.Count -gt 0) {
    Log-Info "Some hives failed: $($failedHives -join ', '). Trying VSS fallback."
    Write-Progress -Activity "VSS Fallback" -Status "Creating shadow copy" -PercentComplete 0
    try {
        $vout = cmd.exe /c "vssadmin create shadow /for=C:" 2>&1
        $deviceObj = $null
        foreach ($l in $vout) { if ($l -match "Shadow Copy Volume: (\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+)") { $deviceObj = $matches[1]; break } }
        if (-not $deviceObj) { foreach ($l in $vout) { if ($l -match "\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+") { $deviceObj = $matches[0]; break } } }
        if ($deviceObj) {
            $mount = Join-Path $env:TEMP ("vss_mount_$([guid]::NewGuid().ToString().Substring(0,6))"); New-Item -ItemType Directory -Force -Path $mount | Out-Null
            cmd.exe /c "mklink /D `"$mount`" `"$deviceObj`"" | Out-Null
            Log-Info "VSS mount: $mount -> $deviceObj"
            $i = 0
            foreach ($h in $failedHives) {
                $i++
                Write-Progress -Activity "VSS Fallback" -Status "Copying $h" -PercentComplete ($i / $failedHives.Count * 100)
                $base = ($h -split "\\")[-1]; $src = Join-Path $mount ("Windows\System32\config\$base"); $dst = Join-Path $hiveFolder ($systemHiveMap[$h])
                try { if (Test-Path $src) { Copy-Item -Path $src -Destination $dst -Force -ErrorAction Stop; Log-Info "VSS copied $src -> $dst" } else { Log-Warn "VSS source not found: $src" } } catch { Log-Err "VSS copy failed for $h : $_" }
            }
            try { cmd.exe /c "rmdir `"$mount`"" | Out-Null } catch {}
        } else { Log-Err "Could not determine VSS device object." }
    } catch { Log-Err "VSS fallback failed: $_" }
}
Write-Progress -Activity "Collecting Registry" -Completed

# -------------------- Event Logs export --------------------
Log-Info "Exporting Event Logs."
Write-Progress -Activity "Exporting Event Logs" -Status "Starting" -PercentComplete 0
$priority = @("Security","System","Application","Setup","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-TaskScheduler/Operational","Microsoft-Windows-WMI-Activity/Operational","Microsoft-Windows-Sysmon/Operational")
try { $allChannels = & wevtutil el 2>&1 | Where-Object { $_ -and $_ -notmatch "Error" } } catch { $allChannels = $priority }
$exportList = $priority + ($allChannels | Where-Object { $priority -notcontains $_ })

$exp=0; $fail=0; $total = $exportList.Count; $i=0
foreach ($ch in $exportList) {
    $i++
    Write-Progress -Activity "Exporting Event Logs" -Status "Processing $ch" -PercentComplete ($i / $total * 100)
    $safe = ($ch -replace '[\\/:*?"<>|]','_' -replace '\s+','_'); $dst = Join-Path $LogsOut ("$safe.evtx")
    try { cmd.exe /c "wevtutil epl `"$ch`" `"$dst`"" | Out-Null; if (Test-Path $dst) { Log-Info "Exported $ch -> $(Split-Path $dst -Leaf)"; $exp++ } else { Log-Warn "wevtutil epl produced no file for $ch"; $fail++ } } catch { Log-Warn "Export failed for ${ch}: $_"; $fail++ }
}
Log-Info "Event logs exported: $exp success, $fail failed"
Write-Progress -Activity "Exporting Event Logs" -Completed

# Raw winevt logs
try {
    $winevt = Join-Path $env:windir "System32\winevt\Logs"
    if (Test-Path $winevt) {
        $rawCopy = Join-Path $LogsOut "raw_winevt"; New-Item -ItemType Directory -Path $rawCopy -Force | Out-Null
        $evtxFiles = Get-ChildItem -Path $winevt -Filter *.evtx -File -ErrorAction SilentlyContinue
        $i = 0
        foreach ($file in $evtxFiles) {
            $i++
            Write-Progress -Activity "Copying Raw Logs" -Status "Processing $($file.Name)" -PercentComplete ($i / $evtxFiles.Count * 100)
            $dst = Join-Path $rawCopy $file.Name
            try { Copy-Item -Path $file.FullName -Destination $dst -Force -ErrorAction Stop; Log-Info "Copied raw log $($file.Name)" } catch { Log-Warn "Could not copy raw log $($file.Name): $_" }
        }
    }
} catch { Log-Warn "Copy raw winevt failed: $_" }
Write-Progress -Activity "Copying Raw Logs" -Completed

# -------------------- Parse EVTX (parallel) --------------------
Log-Info "Parsing event logs (parallel)."
$since = (Get-Date).AddDays(-1 * $LookbackDays)
$evtxFiles = Get-ChildItem -Path $LogsOut -Filter *.evtx -File -Recurse -ErrorAction SilentlyContinue
$logonEvents = New-Object System.Collections.Concurrent.ConcurrentBag[PSObject]
$logoffEvents = New-Object System.Collections.Concurrent.ConcurrentBag[PSObject]
$procEvents = New-Object System.Collections.Concurrent.ConcurrentBag[PSObject]
$psEvents = New-Object System.Collections.Concurrent.ConcurrentBag[PSObject]
$privEvents = New-Object System.Collections.Concurrent.ConcurrentBag[PSObject]
$eventIdsToParse = @(4624,4634,4647,4688,4104,1102,7045,4697,4625,4672,4673)

Write-Progress -Activity "Parsing Events" -Status "Starting" -PercentComplete 0
$evtxFiles | ForEach-Object -Parallel {
    # Import functions for parallel scope
    function Log-Warn { param($m) $t=(Get-Date).ToString('s'); "$t`t[WARN] $m" | Tee-Object -FilePath $using:global:LogFile -Append; Write-Host $m -ForegroundColor Yellow }

    $filter = @{ Path = $_.FullName; StartTime = $using:since; ID = $using:eventIdsToParse }
    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $map = @{}
            try { $xml = [xml]$e.ToXml(); $nodes = $xml.Event.EventData.Data; if ($nodes) { foreach ($n in $nodes) { $nm = $n.Name; if (-not $nm) { $nm = "Field$((Get-Random) -as [int])"}; $map[$nm] = $n.'#text' } } } catch {}
            $rec = [PSCustomObject]@{ TimeCreated = $e.TimeCreated; Id = $e.Id; Provider = $e.ProviderName; Message = ($e.Message -replace "`r`n"," ") -replace "\s{2,}"," "; Data = $map; SourceFile = $_.Name }
            switch ($e.Id) {
                4624 { ($using:logonEvents).Add($rec) }
                { $_ -in @(4634,4647) } { ($using:logoffEvents).Add($rec) }
                4688 { ($using:procEvents).Add($rec) }
                4104 { ($using:psEvents).Add($rec) }
                { $_ -in @(4672,4673) } { ($using:privEvents).Add($rec) }
                default { }
            }
        }
    } catch { Log-Warn "Get-WinEvent fast filter failed for $($_.Name): $_" }
} -ThrottleLimit 4
Write-Progress -Activity "Parsing Events" -Completed

# Convert to arrays
$logonEvents = $logonEvents.ToArray()
$logoffEvents = $logoffEvents.ToArray()
$procEvents = $procEvents.ToArray()
$psEvents = $psEvents.ToArray()
$privEvents = $privEvents.ToArray()
Log-Info ("Collected events: logons={0}, logoffs={1}, proc={2}, ps={3}, priv={4}" -f $logonEvents.Count, $logoffEvents.Count, $procEvents.Count, $psEvents.Count, $privEvents.Count)

# -------------------- Build sessions and durations --------------------
Log-Info "Building sessions and computing durations."
function NormalizeLogonId($s) { if (-not $s) { return $null } $t=$s.ToString(); if ($t -match "0x") { $t = $t.ToLower() } return $t }
$sessions = @()
foreach ($l in $logonEvents) {
    $m = $l.Data
    $lid = $null
    if ($m.ContainsKey("TargetLogonId")) { $lid = $m["TargetLogonId"] } elseif ($m.ContainsKey("SubjectLogonId")) { $lid = $m["SubjectLogonId"] }
    $lid = NormalizeLogonId $lid
    $user = if ($m.ContainsKey("TargetUserName")) { $m["TargetUserName"] } elseif ($m.ContainsKey("SubjectUserName")) { $m["SubjectUserName"] } else { $null }
    $lt = if ($m.ContainsKey("LogonType")) { $m["LogonType"] } else { $null }
    $ip = if ($m.ContainsKey("IpAddress")) { $m["IpAddress"] } else { $null }
    $sessions += [PSCustomObject]@{ User=$user; LogonId=$lid; LogonType=$lt; IP=$ip; StartTime=$l.TimeCreated; EndTime=$null; DurationSeconds=$null; Notes="" }
}
foreach ($lo in $logoffEvents) {
    $m = $lo.Data
    $lid = $null
    if ($m.ContainsKey("TargetLogonId")) { $lid = $m["TargetLogonId"] } elseif ($m.ContainsKey("SubjectLogonId")) { $lid = $m["SubjectLogonId"] }
    $lid = NormalizeLogonId $lid
    $cand = $sessions | Where-Object { $_.LogonId -eq $lid -and $_.EndTime -eq $null } | Sort-Object StartTime
    if ($cand.Count -gt 0) { $s = $cand[0]; $s.EndTime = $lo.TimeCreated; $s.DurationSeconds = ([math]::Round((New-TimeSpan -Start $s.StartTime -End $s.EndTime).TotalSeconds,0)) } else {
        $user = if ($m.ContainsKey("TargetUserName")) { $m["TargetUserName"] } else { $null }
        if ($user) { $cand2 = $sessions | Where-Object { $_.User -eq $user -and $_.EndTime -eq $null -and $_.StartTime -le $lo.TimeCreated } | Sort-Object StartTime; if ($cand2.Count -gt 0) { $s = $cand2[-1]; $s.EndTime = $lo.TimeCreated; $s.DurationSeconds = ([math]::Round((New-TimeSpan -Start $s.StartTime -End $s.EndTime).TotalSeconds,0)) } }
    }
}
foreach ($s in $sessions) { if (-not $s.EndTime) { $s.DurationSeconds = ([math]::Round((New-TimeSpan -Start $s.StartTime -End (Get-Date)).TotalSeconds,0)); $s.Notes += "OPEN_SESSION;" } }

# Heuristics for suspicious sessions
$sessionSusp = @()
foreach ($s in $sessions) {
    $flags = @()
    if ($s.DurationSeconds -lt 60) { $flags += "SHORT(<60s)" }
    if ($s.DurationSeconds -gt (24*3600)) { $flags += "LONG(>24h)" }
    if ($s.LogonType) { [int]$lt=0; if ([int]::TryParse($s.LogonType,[ref]$lt)) { if ($lt -in 3,8,9,10) { $flags += "LOGON_TYPE_$lt" } } }
    if ($s.IP -and $s.IP -notmatch "^(10\.|192\.168\.|172\.|127\.0\.0\.1|::1)") { $flags += "NON_LOCAL_IP" }  # Lateral movement, exclude local
    $h = $s.StartTime.Hour
    if ($h -lt 5 -or $h -gt 22) { $flags += "ODD_HOUR" }
    if ($flags.Count -gt 0) { $s.Notes += ($flags -join ";"); $sessionSusp += $s }
}
$sessions | Sort-Object StartTime | Export-Csv -Path (Join-Path $ParsedOut "sessions_with_duration.csv") -NoTypeInformation -Encoding utf8
$sessionSusp | Sort-Object StartTime | Export-Csv -Path (Join-Path $ParsedOut "suspicious_sessions.csv") -NoTypeInformation -Encoding utf8
Log-Info "Wrote sessions CSVs"

# -------------------- Process creation parsing & heuristics --------------------
Log-Info "Parsing process creation events (4688) with heuristics."
function Detect-Obfuscation($cmd) {
    if ($cmd -match "(?i)-EncodedCommand" -and $cmd.Length -gt 500) { return $true }
    $chars = [char[]]$cmd
    $avg = ($chars | Measure-Object -Average { [int]$_ }).Average
    $stddev = [math]::Sqrt( ($chars | Measure-Object -Average { ([int]$_ - $avg) * ([int]$_ - $avg) }).Average )
    if ($stddev -gt 50) { return $true }
    return $false
}
$procList = @()
$totalProc = $procEvents.Count; $i = 0
foreach ($p in $procEvents) {
    $i++
    Write-Progress -Activity "Parsing Processes" -Status "Processing event $i of $totalProc" -PercentComplete ($i / $totalProc * 100)
    $m = $p.Data
    $user = if ($m.ContainsKey("SubjectUserName")) { $m["SubjectUserName"] } elseif ($m.ContainsKey("TargetUserName")) { $m["TargetUserName"] } else { $null }
    $logonId = if ($m.ContainsKey("SubjectLogonId")) { NormalizeLogonId $m["SubjectLogonId"] } else { $null }
    $procPath = if ($m.ContainsKey("NewProcessName")) { $m["NewProcessName"] } elseif ($m.ContainsKey("ProcessName")) { $m["ProcessName"] } else { $null }
    $cmd = if ($m.ContainsKey("CommandLine")) { $m["CommandLine"] } else { $null }
    $time = $p.TimeCreated
    $rec = [PSCustomObject]@{ TimeCreated=$time; User=$user; LogonId=$logonId; ProcessPath=$procPath; CommandLine=$cmd; Suspicious=$false; SuspiciousNotes="" }
    $notes=@(); $isS=$false
    if ($cmd -and $cmd -match "(?i)-EncodedCommand|-enc") { $isS=$true; $notes += "EncodedPowerShell" }
    if ($procPath -and $procPath.ToLower() -match "\\temp\\|\\appdata\\roaming\\|\\appdata\\local\\|\\downloads\\") { $isS=$true; $notes += "PathInTempOrAppData" }
    if ($cmd -and $cmd -match "(?i)bitsadmin|certutil|rundll32|regsvr32|mshta|cscript|wscript|powershell.*IEX|Invoke-WebRequest") { $isS=$true; $notes += "KnownAbuseTool" }
    if ($procPath -and $procPath.Length -gt 400) { $isS=$true; $notes += "LongPath" }
    if ($cmd -and (Detect-Obfuscation $cmd)) { $isS=$true; $notes += "ObfuscatedCmd" }
    $rec.Suspicious = $isS; $rec.SuspiciousNotes = ($notes -join ";")
    $procList += $rec
}
foreach ($pr in $procList) {
    if ($pr.LogonId) {
        $s = $sessions | Where-Object { $_.LogonId -eq $pr.LogonId } | Select-Object -First 1
        if ($s) { $pr | Add-Member -NotePropertyName SessionStart -NotePropertyValue $s.StartTime -Force; $pr | Add-Member -NotePropertyName SessionEnd -NotePropertyValue $s.EndTime -Force }
    }
}
$procList | Sort-Object TimeCreated | Export-Csv -Path (Join-Path $ParsedOut "process_creations.csv") -NoTypeInformation -Encoding utf8
($procList | Where-Object { $_.Suspicious -eq $true }) | Sort-Object TimeCreated | Export-Csv -Path (Join-Path $ParsedOut "suspicious_processes.csv") -NoTypeInformation -Encoding utf8
Log-Info "Wrote process CSVs"
Write-Progress -Activity "Parsing Processes" -Completed

# -------------------- PowerShell scriptblock analysis --------------------
Log-Info "Analyzing PowerShell scriptblock events (4104)."
$psParsed = @()
$totalPS = $psEvents.Count; $i = 0
foreach ($pe in $psEvents) {
    $i++
    Write-Progress -Activity "Parsing PowerShell Events" -Status "Processing event $i of $totalPS" -PercentComplete ($i / $totalPS * 100)
    $m = $pe.Data
    $user = if ($m.ContainsKey("SubjectUserName")) { $m["SubjectUserName"] } else { $null }
    $script = if ($m.ContainsKey("ScriptBlockText")) { $m["ScriptBlockText"] } elseif ($m.ContainsKey("ScriptBlockId")) { $m["ScriptBlockId"] } else { $null }
    $peRec = [PSCustomObject]@{ TimeCreated=$pe.TimeCreated; User=$user; ScriptBlockText = $script; Source = $pe.SourceFile; Suspicious=$false; Notes="" }
    if ($script -and $script -match "(?i)FromBase64String|FromBase64|-EncodedCommand|IEX|Invoke-Expression|DownloadString|Start-Process|New-Object Net.WebClient") {
        $peRec.Suspicious = $true
        $peRec.Notes = ($script -replace "[\r\n]+"," ") -replace "\s{2,}"," "
    }
    if ($script -and (Detect-Obfuscation $script)) { $peRec.Suspicious = $true; $peRec.Notes += ";ObfuscatedScript" }
    $psParsed += $peRec
}
if ($psParsed.Count -gt 0) { $psParsed | Sort-Object TimeCreated | Export-Csv -Path (Join-Path $ParsedOut "powershell_scriptblocks.csv") -NoTypeInformation -Encoding utf8; Log-Info "Wrote powershell_scriptblocks.csv" }
Write-Progress -Activity "Parsing PowerShell Events" -Completed

# -------------------- Network collection & correlation --------------------
Log-Info "Collecting network artifacts."
Write-Progress -Activity "Collecting Network Artifacts" -Status "Starting" -PercentComplete 0
try { Get-NetTCPConnection -ErrorAction SilentlyContinue | Export-Csv -Path (Join-Path $NetOut "TCPConnections_raw.csv") -NoTypeInformation -Encoding utf8; Log-Info "Saved TCP connections" } catch { Log-Warn "Get-NetTCPConnection failed" }
try { netstat -ano | Out-File -FilePath (Join-Path $NetOut "netstat.txt") -Encoding utf8; Log-Info "Saved netstat" } catch { Log-Warn "netstat failed" }
try { arp -a | Out-File -FilePath (Join-Path $NetOut "arp.txt") -Encoding utf8; Log-Info "Saved arp" } catch { Log-Warn "arp failed" }
try { ipconfig /all | Out-File -FilePath (Join-Path $NetOut "ipconfig_all.txt") -Encoding utf8; Log-Info "Saved ipconfig /all" } catch { Log-Warn "ipconfig failed" }
try { ipconfig /displaydns | Out-File -FilePath (Join-Path $NetOut "dns_cache.txt") -Encoding utf8; Log-Info "Saved DNS cache" } catch { Log-Warn "dns cache failed" }
# Firewall logs
try { Copy-Item -Path "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -Destination (Join-Path $NetOut "firewall.log") -Force -ErrorAction SilentlyContinue; Log-Info "Copied firewall log" } catch { Log-Warn "Firewall log copy failed" }
# Parse firewall: count blocked
try {
    $fwLog = Join-Path $NetOut "firewall.log"
    if (Test-Path $fwLog) {
        $blocked = Get-Content $fwLog | Where-Object { $_ -match "DROP" } | Group-Object { $_.Split()[5] }
        $blocked | Select-Object Name, Count | Export-Csv (Join-Path $ParsedOut "firewall_blocks.csv") -NoTypeInformation -Encoding utf8
        Log-Info "Parsed firewall blocks"
    }
} catch { Log-Warn "Firewall parsing failed: $_" }
Write-Progress -Activity "Collecting Network Artifacts" -Completed

# Correlate TCP connections
$netCorrelated = @()
try {
    $tcp = Import-Csv -Path (Join-Path $NetOut "TCPConnections_raw.csv") -ErrorAction SilentlyContinue
    $totalTcp = $tcp.Count; $i = 0
    foreach ($row in $tcp) {
        $i++
        Write-Progress -Activity "Correlating Network" -Status "Processing connection $i of $totalTcp" -PercentComplete ($i / $totalTcp * 100)
        $own = $row.OwningProcess
        if ($own) {
            try { $g = Get-Process -Id $own -ErrorAction SilentlyContinue } catch { $g = $null }
            $entry = [PSCustomObject]@{ OwningProcess = $own; ProcessName = if ($g) { $g.ProcessName } else { $null }; LocalAddress = $row.LocalAddress; LocalPort = $row.LocalPort; RemoteAddress = $row.RemoteAddress; RemotePort = $row.RemotePort; State = $row.State }
            $netCorrelated += $entry
        }
    }
    if ($netCorrelated.Count -gt 0) { $netCorrelated | Export-Csv -Path (Join-Path $NetOut "TCPConnections_Correlated.csv") -NoTypeInformation -Encoding utf8; Log-Info "Wrote TCPConnections_Correlated.csv" }
} catch { Log-Warn "Network/proc correlation failed: $_" }
Write-Progress -Activity "Correlating Network" -Completed

# Reverse DNS
$netResolution = @()
try {
    $extips = ($netCorrelated | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch "^(10\.|192\.168\.|172\.|127\.0\.0\.1|::1)" } | Select-Object -ExpandProperty RemoteAddress -Unique)
    $totalIps = $extips.Count; $i = 0
    foreach ($ip in $extips) {
        $i++
        Write-Progress -Activity "Resolving DNS" -Status "Processing IP $ip" -PercentComplete ($i / $totalIps * 100)
        try { $host = [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $host = $null }
        $netResolution += [PSCustomObject]@{ IP=$ip; HostName=$host }
    }
    if ($netResolution.Count -gt 0) { $netResolution | Export-Csv -Path (Join-Path $NetOut "remote_dns_resolution.csv") -NoTypeInformation -Encoding utf8; Log-Info "Wrote remote_dns_resolution.csv" }
} catch { Log-Warn "Reverse DNS resolution failed or timed out" }
Write-Progress -Activity "Resolving DNS" -Completed

# -------------------- System snapshots & persistence --------------------
Log-Info "Collecting system snapshots."
Write-Progress -Activity "Collecting System Snapshots" -Status "Starting" -PercentComplete 0
try { systeminfo | Out-File -FilePath (Join-Path $SysOut "systeminfo.txt") -Encoding utf8; Log-Info "Saved systeminfo" } catch { Log-Warn "systeminfo failed" }
try { tasklist /v | Out-File -FilePath (Join-Path $SysOut "tasklist_v.txt") -Encoding utf8; Log-Info "Saved tasklist /v" } catch { Log-Warn "tasklist failed" }
try { Get-Process | Select-Object Id, ProcessName, @{N='Path';E={(try{$_.Path}catch{'N/A'})}}, CPU | Export-Csv -Path (Join-Path $SysOut "getprocess.csv") -NoTypeInformation -Encoding utf8; Log-Info "Saved Get-Process" } catch { Log-Warn "Get-Process failed" }
try { Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName | Export-Csv -Path (Join-Path $PersistOut "services.csv") -NoTypeInformation -Encoding utf8; Log-Info "Saved services list" } catch { Log-Warn "services list failed" }
try { schtasks /query /fo LIST /v | Out-File -FilePath (Join-Path $PersistOut "schtasks_list.txt") -Encoding utf8; Log-Info "Saved schtasks" } catch { Log-Warn "schtasks failed" }
try { $startupUser = Join-Path ([Environment]::GetFolderPath("ApplicationData")) "Microsoft\Windows\Start Menu\Programs\Startup"; if (Test-Path $startupUser) { Copy-Item -Path $startupUser -Destination (Join-Path $PersistOut "StartupFolder_User") -Recurse -Force -ErrorAction SilentlyContinue; Log-Info "Copied StartupFolder_User" } } catch { Log-Warn "copy startup user failed" }
try { $startupAll = Join-Path ([Environment]::GetFolderPath("ProgramData")) "Microsoft\Windows\Start Menu\Programs\StartUp"; if (Test-Path $startupAll) { Copy-Item -Path $startupAll -Destination (Join-Path $PersistOut "StartupFolder_All") -Recurse -Force -ErrorAction SilentlyContinue; Log-Info "Copied StartupFolder_All" } } catch { Log-Warn "copy startup all failed" }
Write-Progress -Activity "Collecting System Snapshots" -Completed

# -------------------- Prefetch / Amcache (internal parsing) --------------------
Log-Info "Collecting and parsing Prefetch/Amcache."
Write-Progress -Activity "Collecting Prefetch/Amcache" -Status "Starting" -PercentComplete 0
try { 
    $prefetch = Join-Path $env:SystemRoot "Prefetch"; 
    if (Test-Path $prefetch) { 
        $prefDst = Join-Path $OtherOut "Prefetch"; 
        Copy-Item -Path $prefetch -Destination $prefDst -Recurse -Force -ErrorAction SilentlyContinue; 
        Log-Info "Copied Prefetch"
        # Basic parsing: list files with metadata
        Get-ChildItem "$prefDst\*.pf" | Select-Object Name, LastWriteTime, @{N='SizeKB';E={[math]::Round($_.Length/1KB,2)}} | Export-Csv (Join-Path $ParsedOut "Prefetch_Basic.csv") -NoTypeInformation -Encoding utf8
        Log-Info "Parsed basic Prefetch metadata"
    } 
} catch { Log-Warn "Prefetch copy failed" }
try { 
    $amcache = Join-Path $env:SystemRoot "System32\config\Amcache.hve"; 
    if (Test-Path $amcache) { 
        Copy-Item -Path $amcache -Destination (Join-Path $OtherOut "Amcache.hve") -Force -ErrorAction SilentlyContinue; 
        Log-Info "Copied Amcache.hve"
        # Basic parsing: reg query
        $tempHive = "HKLM\TempAmcache"
        try { 
            reg load $tempHive (Join-Path $OtherOut "Amcache.hve") | Out-Null
            Get-ItemProperty "HKLM:\TempAmcache\Root\InventoryApplication" | Export-Csv (Join-Path $ParsedOut "Amcache_Basic.csv") -NoTypeInformation -Encoding utf8
            Log-Info "Parsed basic Amcache data"
            reg unload $tempHive | Out-Null
        } catch { Log-Warn "Amcache parsing failed: $_" }
    } 
} catch { Log-Warn "Amcache copy failed" }
Write-Progress -Activity "Collecting Prefetch/Amcache" -Completed

# If external tools present (original logic)
if (Test-Path (Join-Path $toolsPath "PECmd.exe")) {
    try {
        $outCsv = Join-Path $ParsedOut "Prefetch_Parsed_PECmd.csv"
        & (Join-Path $toolsPath "PECmd.exe") -d $prefDst --csv $outCsv --quiet 2>&1 | Out-Null
        if (Test-Path $outCsv) { Log-Info "PECmd parsed Prefetch -> $outCsv" }
    } catch { Log-Warn "PECmd run failed: $_" }
}
if (Test-Path (Join-Path $toolsPath "AmcacheParser.exe")) {
    try {
        $amOut = Join-Path $ParsedOut "Amcache_Parsed.csv"
        & (Join-Path $toolsPath "AmcacheParser.exe") -f (Join-Path $OtherOut "Amcache.hve") --csv $amOut --quiet 2>&1 | Out-Null
        if (Test-Path $amOut) { Log-Info "AmcacheParser parsed Amcache -> $amOut" }
    } catch { Log-Warn "AmcacheParser run failed: $_" }
}

# -------------------- Browser collection --------------------
Log-Info "Collecting browser artifacts."
Write-Progress -Activity "Collecting Browser Artifacts" -Status "Starting" -PercentComplete 0
$chromiumBrowsers = @{
    "Chrome" = "AppData\Local\Google\Chrome\User Data\Default"
    "Edge"   = "AppData\Local\Microsoft\Edge\User Data\Default"
    "Brave"  = "AppData\Local\BraveSoftware\Brave-Browser\User Data\Default"
}
$goldChromiumFiles = @("History","Cookies","Login Data","Web Data","Bookmarks","Preferences","Favicons")
$users = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
$totalUsers = $users.Count; $i = 0
foreach ($u in $users) {
    $i++
    Write-Progress -Activity "Collecting Browser Artifacts" -Status "Processing user $($u.Name)" -PercentComplete ($i / $totalUsers * 100)
    foreach ($b in $chromiumBrowsers.GetEnumerator()) {
        $src = Join-Path $u.FullName $b.Value
        if (Test-Path $src) {
            $dst = Join-Path $BrowserOut ("$($u.Name)_$($b.Key)"); New-Item -Path $dst -ItemType Directory -Force | Out-Null
            foreach ($f in $goldChromiumFiles) {
                $srcFile = Join-Path $src $f
                if (Test-Path $srcFile) { Copy-Item -Path $srcFile -Destination $dst -Recurse -Force -ErrorAction SilentlyContinue; Log-Info "Copied $($b.Key) artifact $f for $($u.Name)" }
            }
            $extPath = Join-Path $src "Extensions"
            if (Test-Path $extPath) {
                $extDst = Join-Path $dst "Extensions"; New-Item -Path $extDst -ItemType Directory -Force | Out-Null
                Get-ChildItem -Path $extPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $manifest = Get-ChildItem -Path $_.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($manifest) { Copy-Item -Path $manifest.FullName -Destination (Join-Path $extDst ("$($_.Name)_manifest.json")) -Force -ErrorAction SilentlyContinue }
                }
                Log-Info "Saved extension manifests for $($b.Key) for $($u.Name)"
            }
        }
    }
    # Other Chromium-like
    try {
        $localApps = Get-ChildItem -Path (Join-Path $u.FullName "AppData\Local") -Directory -ErrorAction SilentlyContinue
        foreach ($app in $localApps) {
            $maybe = Join-Path $app.FullName "User Data\Default\History"
            if (Test-Path $maybe) {
                $name = $app.Name
                if ($chromiumBrowsers.Keys -notcontains $name) {
                    $dst = Join-Path $BrowserOut ("$($u.Name)_$name"); New-Item -Path $dst -ItemType Directory -Force | Out-Null
                    foreach ($f in $goldChromiumFiles) {
                        $sf = Join-Path (Join-Path $app.FullName "User Data\Default") $f
                        if (Test-Path $sf) { Copy-Item -Path $sf -Destination $dst -Recurse -Force -ErrorAction SilentlyContinue }
                    }
                    $extPath = Join-Path (Join-Path $app.FullName "User Data\Default") "Extensions"
                    if (Test-Path $extPath) {
                        $extDst = Join-Path $dst "Extensions"; New-Item -Path $extDst -ItemType Directory -Force | Out-Null
                        Get-ChildItem -Path $extPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                            $manifest = Get-ChildItem -Path $_.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                            if ($manifest) { Copy-Item -Path $manifest.FullName -Destination (Join-Path $extDst ("$($_.Name)_manifest.json")) -Force -ErrorAction SilentlyContinue }
                        }
                    }
                    Log-Info "Saved Chromium-based browser ($name) artifacts for $($u.Name)"
                }
            }
        }
    } catch { Log-Warn "Discovery of extra chromium apps failed for user $($u.Name): $_" }

    # Firefox
    try {
        $ffProfilesPath = Join-Path $u.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path $ffProfilesPath) {
            $profile = Get-ChildItem -Path $ffProfilesPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($profile) {
                $dst = Join-Path $BrowserOut ("$($u.Name)_Firefox"); New-Item -Path $dst -ItemType Directory -Force | Out-Null
                $ffFiles = @("places.sqlite","cookies.sqlite","logins.json","formhistory.sqlite","addons.json","prefs.js")
                foreach ($f in $ffFiles) { $sf = Join-Path $profile.FullName $f; if (Test-Path $sf) { Copy-Item -Path $sf -Destination $dst -Force -ErrorAction SilentlyContinue; Log-Info "Copied Firefox $f for $($u.Name)" } }
                $addons = Join-Path $profile.FullName "addons.json"; if (Test-Path $addons) { Copy-Item -Path $addons -Destination (Join-Path $dst "extensions_list.json") -Force -ErrorAction SilentlyContinue }
            }
        }
    } catch { Log-Warn "Firefox copy failed for user $($u.Name): $_" }
}
Write-Progress -Activity "Collecting Browser Artifacts" -Completed

# Browser history (basic parsing if no sqlite3)
if (Test-Path (Join-Path $toolsPath "sqlite3.exe")) {
    Log-Info "sqlite3 found: extracting top URLs."
    $histFiles = Get-ChildItem -Path $BrowserOut -Recurse -Filter "History" -File -ErrorAction SilentlyContinue
    $totalHist = $histFiles.Count; $i = 0
    foreach ($h in $histFiles) {
        $i++
        Write-Progress -Activity "Parsing Browser History" -Status "Processing $($h.Name)" -PercentComplete ($i / $totalHist * 100)
        $outCsv = (Join-Path $ParsedOut ($h.Directory.Name + "_History_top_urls.csv"))
        try {
            & (Join-Path $toolsPath "sqlite3.exe") -cmd ".mode csv" -cmd ".headers on" "$($h.FullName)" "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY visit_count DESC LIMIT 200;" > $outCsv 2>&1
            if (Test-Path $outCsv) { Log-Info "Extracted top URLs -> $outCsv" }
        } catch { Log-Warn "sqlite3 query failed for $($h.FullName): $_" }
    }
} else {
    Log-Info "sqlite3.exe not found; attempting basic history parsing."
    $histFiles = Get-ChildItem -Path $BrowserOut -Recurse -Filter "History" -File -ErrorAction SilentlyContinue
    foreach ($h in $histFiles) {
        $outTxt = Join-Path $ParsedOut ($h.Directory.Name + "_History_basic.txt")
        try { Get-Content $h.FullName -Raw | Select-String "http" | Out-File $outTxt -Encoding utf8; Log-Info "Basic history parse -> $outTxt" } catch { Log-Warn "Basic history parse failed for $($h.FullName)" }
    }
}
Write-Progress -Activity "Parsing Browser History" -Completed

# -------------------- SRUDB and Memory --------------------
Log-Info "Collecting SRUDB and memory minidump."
Write-Progress -Activity "Collecting SRUDB/Memory" -Status "Starting" -PercentComplete 0
try { 
    $sru = Join-Path $env:SystemRoot "System32\sru\SRUDB.dat"
    if (Test-Path $sru) { 
        Copy-Item $sru (Join-Path $OtherOut "SRUDB.dat") -Force
        esentutl /mh $sru | Out-File (Join-Path $ParsedOut "SRUDB_info.txt") -Encoding utf8
        Log-Info "Collected SRUDB and basic info"
    }
} catch { Log-Warn "SRUDB collection failed: $_" }
# Minidump (basic for lsass)
try {
    $lsass = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
    if ($lsass) {
        $dumpPath = Join-Path $OtherOut "lsass_minidump.dmp"
        # Simplified minidump (requires external module or .NET, placeholder here)
        Log-Info "Minidump placeholder for lsass (advanced implementation needed)"
    }
} catch { Log-Warn "Minidump failed: $_" }
Write-Progress -Activity "Collecting SRUDB/Memory" -Completed

# -------------------- Hashing candidates --------------------
Log-Info "Hashing candidate executables."
Write-Progress -Activity "Hashing Files" -Status "Starting" -PercentComplete 0

# Initialize thread-safe collection
$hashResults = New-Object System.Collections.Concurrent.ConcurrentBag[PSObject]
$candidates = @()

if ($HashAll.IsPresent) {
    $paths = @([Environment]::GetFolderPath("ProgramFiles"), [Environment]::GetFolderPath("ProgramFilesX86"), "C:\Users")
    $candidates = Get-ChildItem -Path $paths -Include *.exe -File -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 100
} else {
    foreach ($r in $procList) {
        if ($r.ProcessPath) {
            $p = $r.ProcessPath
            try { $exp = [Environment]::ExpandEnvironmentVariables($p) } catch { $exp = $p }
            if ($exp -match '^[^\"]*\.(exe)\b') { $exe = $matches[0] } else { $exe = $exp.Split(" ")[0] }
            if ($exe -and (Test-Path $exe)) { $candidates += $exe }
        }
    }
}
$candidates = $candidates | Select-Object -Unique
$totalCand = $candidates.Count; $i = 0

$candidates | ForEach-Object -Parallel {
    # Import Log functions for parallel scope
    function Log-Info { param($m) $t=(Get-Date).ToString('s'); "$t`t[INFO] $m" | Tee-Object -FilePath $using:global:LogFile -Append; Write-Host $m -ForegroundColor Cyan }
    function Log-Warn { param($m) $t=(Get-Date).ToString('s'); "$t`t[WARN] $m" | Tee-Object -FilePath $using:global:LogFile -Append; Write-Host $m -ForegroundColor Yellow }

    $file = $_
    $localI = [System.Threading.Interlocked]::Increment([ref]$using:i)
    Write-Progress -Activity "Hashing Files" -Status "Processing $file" -PercentComplete ($localI / $using:totalCand * 100)
    try {
        $h = Get-FileHash -Path $file -Algorithm SHA256 -ErrorAction Stop
        ($using:hashResults).Add([PSCustomObject]@{ File=$file; SHA256=$h.Hash; Found=1 })
        Log-Info "Hashed $file"
    } catch {
        ($using:hashResults).Add([PSCustomObject]@{ File=$file; SHA256=$null; Found=0 })
        Log-Warn "Hash failed for ${file}: $_"
    }
} -ThrottleLimit 4

# Convert to array
$hashResultsArray = $hashResults.ToArray()
if ($hashResultsArray.Count -gt 0) { $hashResultsArray | Export-Csv -Path (Join-Path $ParsedOut "file_hashes.csv") -NoTypeInformation -Encoding utf8; Log-Info "Wrote file_hashes.csv" } else { Log-Info "No files hashed." }
Write-Progress -Activity "Hashing Files" -Completed

# -------------------- Visual Display --------------------
Log-Info "Generating visual output."
Write-Progress -Activity "Generating Visuals" -Status "Preparing tables and charts" -PercentComplete 0
# GridView for suspicious
$sessionSusp | Select-Object User, LogonType, IP, StartTime, DurationSeconds, Notes | Out-GridView -Title "Suspicious Sessions" -PassThru
$procList | Where-Object { $_.Suspicious } | Select-Object TimeCreated, User, ProcessPath, CommandLine, SuspiciousNotes | Out-GridView -Title "Suspicious Processes" -PassThru

# ASCII chart for process count per day
$procByDay = $procList | Group-Object { $_.TimeCreated.ToString("yyyy-MM-dd") } | Sort-Object Name
Write-Host "Process Count per Day (ASCII Chart):"
foreach ($g in $procByDay) {
    $bar = "#" * [math]::Round($g.Count / 10)
    Write-Host "$($g.Name): $bar ($($g.Count))"
}
Write-Progress -Activity "Generating Visuals" -Completed

# -------------------- Analysis Report --------------------
Log-Info "Building analysis report."
Write-Progress -Activity "Building Report" -Status "Starting" -PercentComplete 0
$analysisTxt = Join-Path $AnalysisOut "analysis_report.txt"
$lines = @()
$lines += "Forensic Analyzer - Initial Analysis Report"
$lines += "CollectedAt: $((Get-Date).ToString('o'))"
$lines += ""
$lines += "[Suspicious Logons]"
if ($sessionSusp.Count -gt 0) { foreach ($ss in $sessionSusp) { $lines += ("User: {0} | LogonType: {1} | IP: {2} | Start: {3} | Duration(s): {4} | Notes: {5}" -f $ss.User, $ss.LogonType, $ss.IP, $ss.StartTime, $ss.DurationSeconds, $ss.Notes) } } else { $lines += "None detected." }
$lines += ""
$lines += "[Top Suspicious Processes]"
$suspProcs = $procList | Where-Object { $_.Suspicious -eq $true } | Sort-Object TimeCreated -Descending
if ($suspProcs.Count -gt 0) { foreach ($p in $suspProcs) { $lines += ("Time: {0} | User: {1} | Proc: {2} | Cmd: {3} | Notes: {4}" -f $p.TimeCreated, $p.User, $p.ProcessPath, ($p.CommandLine -replace "`r`n"," "), $p.SuspiciousNotes) } } else { $lines += "No suspicious processes found." }
$lines += ""
$lines += "[PowerShell suspicious scriptblocks]"
$psSus = $psParsed | Where-Object { $_.Suspicious -eq $true } | Sort-Object TimeCreated -Descending
if ($psSus.Count -gt 0) { foreach ($pe in $psSus) { $snippet = if ($pe.ScriptBlockText) { ($pe.ScriptBlockText -replace "[\r\n]+"," ") -replace "\s{2,}"," " } else { "<no-script-text>" }; $lines += ("Time: {0} | User: {1} | Snippet: {2}" -f $pe.TimeCreated, $pe.User, ($snippet.Substring(0,[math]::Min(800,$snippet.Length)))) } } else { $lines += "No suspicious PowerShell scriptblocks found." }
$lines += ""
$lines += "[Browser History Analysis]"
$histFiles = Get-ChildItem -Path $ParsedOut -Filter "*History_top_urls.csv" -File -ErrorAction SilentlyContinue
if ($histFiles.Count -gt 0) { 
    foreach ($h in $histFiles) { 
        $lines += "History from $($h.BaseName):"
        Import-Csv $h.FullName | Select-Object -First 10 | ForEach-Object { $lines += "URL: $($_.url) | Title: $($_.title) | Visits: $($_.visit_count) | Last Visit: $($_.last_visit_time)" } 
        $lines += ""
    } 
} else { $lines += "No browser history data available." }
$lines += ""
$lines += "[Event Log Analysis (Standard Events)]"
$standardEvents = $logonEvents + $logoffEvents + $procEvents + $psEvents
if ($standardEvents.Count -gt 0) { 
    $standardEvents | Sort-Object TimeCreated -Descending | Select-Object -First 20 | ForEach-Object { $lines += "Time: $($_.TimeCreated) | ID: $($_.Id) | Message: $($_.Message)" } 
} else { $lines += "No standard events found." }
$lines += ""
$lines += "[Summary counts]"
$lines += ("Event files exported: {0}" -f (Get-ChildItem -Path $LogsOut -Filter *.evtx -File -Recurse -ErrorAction SilentlyContinue).Count)
$lines += ("Sessions total: {0} | Suspicious sessions: {1}" -f $sessions.Count, $sessionSusp.Count)
$lines += ("Process creation events parsed: {0} | Suspicious processes: {1}" -f $procList.Count, ($procList | Where-Object { $_.Suspicious -eq $true }).Count)
$lines += ("PowerShell events parsed: {0} | Suspicious: {1}" -f $psParsed.Count, ($psParsed | Where-Object { $_.Suspicious -eq $true }).Count)
$lines += ("Hashed files: {0}" -f $hashResultsArray.Count)
$lines += ""
$lines | Out-File -FilePath $analysisTxt -Encoding utf8
Log-Info "Wrote analysis text: $analysisTxt"

# JSON summary
$summary = [PSCustomObject]@{
    Host = $HostName
    CollectedAt = (Get-Date).ToString("o")
    LookbackDays = $LookbackDays
    EvtxFiles = (Get-ChildItem -Path $LogsOut -Filter *.evtx -File -Recurse -ErrorAction SilentlyContinue).Count
    SessionsCount = $sessions.Count
    SuspiciousSessions = $sessionSusp.Count
    ProcessEvents = $procList.Count
    SuspiciousProcesses = ($procList | Where-Object { $_.Suspicious -eq $true }).Count
    PowerShellEvents = $psParsed.Count
    SuspiciousPowerShell = ($psParsed | Where-Object { $_.Suspicious -eq $true }).Count
    HashCount = $hashResultsArray.Count
    OutputFolder = $OutRoot
}
$summary | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $OutRoot "summary.json") -Encoding utf8
Log-Info "Wrote summary.json"

# HTML report
$report = Join-Path $OutRoot "report.html"
$html = @"
<!doctype html><html><head><meta charset='utf-8'><title>Forensic Analyzer Report - $HostName</title>
<style>body{font-family:Segoe UI,Arial} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:6px;font-size:12px} th{background:#f2f2f2} .bad{background:#ffd6d6}</style>
</head><body>
<h1>Forensic Analyzer Report - $HostName</h1>
<p>Collected at: $((Get-Date).ToString('s'))</p>
<ul>
<li>EVTX files scanned: $((Get-ChildItem -Path $LogsOut -Filter *.evtx -File -Recurse -ErrorAction SilentlyContinue).Count)</li>
<li>Sessions: $($sessions.Count) (Suspicious: $($sessionSusp.Count))</li>
<li>Process events: $($procList.Count) (Suspicious: $(( $procList | Where-Object { $_.Suspicious -eq $true }).Count ))</li>
<li>PowerShell events (4104): $($psParsed.Count) (Suspicious: $(( $psParsed | Where-Object { $_.Suspicious -eq $true }).Count ))</li>
<li>Hashed files: $($hashResultsArray.Count)</li>
</ul>
<h2>Sample suspicious processes</h2>
<table><tr><th>Time</th><th>User</th><th>Process</th><th>CmdLine</th><th>Notes</th></tr>
"@
$top = $procList | Where-Object { $_.Suspicious -eq $true } | Sort-Object TimeCreated -Descending | Select-Object -First 50
foreach ($p in $top) {
    $procPathHtml = if ($p.ProcessPath) { [System.Web.HttpUtility]::HtmlEncode($p.ProcessPath) } else { "" }
    $cmdHtml = if ($p.CommandLine) { [System.Web.HttpUtility]::HtmlEncode($p.CommandLine) } else { "" }
    $html += "<tr class='bad'><td>$($p.TimeCreated)</td><td>$($p.User)</td><td>$procPathHtml</td><td>$cmdHtml</td><td>$([System.Web.HttpUtility]::HtmlEncode($p.SuspiciousNotes))</td></tr>`n"
}
$html += "</table></body></html>"
$html | Out-File -FilePath $report -Encoding utf8
Log-Info "Wrote HTML report: $report"
Write-Progress -Activity "Building Report" -Completed

# -------------------- Compress output --------------------
Log-Info "Compressing output to ZIP."
Write-Progress -Activity "Compressing Output" -Status "Starting" -PercentComplete 0
$zip = Join-Path $desktop ("Forensic_Artifacts_${HostName}_$ts.zip")
try { Compress-Archive -Path (Join-Path $OutRoot '*') -DestinationPath $zip -Force; Log-Info "Compressed to: $zip" } catch { Log-Err "Compression failed: $_" }
Write-Progress -Activity "Compressing Output" -Completed

Log-Info "Collection & analysis finished. Output folder: $OutRoot"
"=== Forensic Analyzer Collector finished: $((Get-Date).ToString('o')) ===" | Out-File -FilePath $global:LogFile -Append -Encoding utf8
Start-Process $OutRoot
