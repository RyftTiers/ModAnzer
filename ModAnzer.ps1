<#
.SYNOPSIS
    ModAnzer - finds every Minecraft mods folder on this PC and checks the mods in it.

.DESCRIPTION
    Based on HabibiModAnalyzer by HadronCollision
    (https://github.com/HadronCollision/PowershellScripts).

    What it does:
      * Auto-detects mods folders for vanilla .minecraft, CurseForge, Modrinth App,
        Prism / PolyMC / MultiMC, ATLauncher, GDLauncher, Technic, Dawn (Feather), Lunar,
        and any "dot" client folder (.badlion, ...) - no path pasting needed.
      * Also picks up the game folder of any Minecraft that is running right now.
      * Hashes each .jar (SHA1) and looks the hashes up on Modrinth (batched) and
        Megabase and CurseForge. Only hashes/fingerprints are sent - never your files.
      * Mods that are not recognised are opened in memory (no temp extraction) and
        searched, including nested jars, for well-known cheat module names.

    Injection Checker: launch options, loaded DLLs, a read-only scan of Minecraft's
    memory for cheat names and hidden (manual-mapped) programs, then a live watch.

    System Check: BAM and Prefetch execution history, logging services, cleared event
    logs, PowerShell history, USB drives, Recycle Bin, recent downloads, VM detection
    and Minecraft account names (names only).

    Read-only: nothing is modified, uploaded, or installed.

.PARAMETER Path
    One or more folders to scan instead of auto-detection.

.PARAMETER Offline
    Skip the online lookups and only do the cheat-string scan.

.PARAMETER SkipIntro
    Don't show the "what this script does" notice or wait for Enter.

.PARAMETER Mode
    'mods' (Mod Analyzer), 'injection' (Injection Checker), 'system' (System Check)
    or 'full' (all three), skipping the start menu.

.PARAMETER LiveSeconds
    Injection Checker: stop the live watch after this many seconds
    (default: keep watching until you press Q).

.PARAMETER NoSend
    Don't offer to send the results to staff at the end.

.PARAMETER Launcher
    Mod Analyzer: 'all' to scan every launcher, or part of a launcher's name
    (e.g. 'CurseForge'), instead of asking.

.PARAMETER StopFile
    Injection Checker: the live watch stops when this file appears.

.PARAMETER ReportOut
    Write the results report (JSON, user folders hidden) to this file instead of
    asking to send it. Used by ModAnzer.exe, which sends it with its own button.

.PARAMETER NoPause
    Don't wait for Enter at the end (by default it waits, so the window
    stays open when started with right-click > Run with PowerShell).

.EXAMPLE
    .\ModAnzer.ps1
.EXAMPLE
    .\ModAnzer.ps1 -Path "D:\Games\MyPack\mods"
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [switch]$Offline,
    [switch]$SkipIntro,
    [switch]$NoPause,
    [string]$Mode = '',
    [int]$LiveSeconds = 0,
    [switch]$NoSend,
    [string]$Launcher = '',
    [string]$StopFile = '',
    [string]$ReportOut = ''
)

$ErrorActionPreference = 'Stop'

# If anything goes wrong, show the error and keep the window open instead of closing.
trap {
    Write-Host
    Write-Host 'ModAnzer stopped because of an error:' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ("(line {0})" -f $_.InvocationInfo.ScriptLineNumber) -ForegroundColor DarkGray
    if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
    exit 2
}
$ProgressPreference    = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# ---------------------------------------------------------------- settings

# Strong names: unusual words that are basically only used by cheats.
# Matched case-sensitively anywhere in a mod's files.
$CheatStrings = @(
    'AnchorTweaks', 'AutoAnchor', 'AutoCrystal', 'AutoDoubleHand', 'AutoHitCrystal',
    'AutoPot', 'AutoTotem', 'InventoryTotem', 'JumpReset', 'LegitTotem', 'PingSpoof',
    'SelfDestruct', 'ShieldBreaker', 'TriggerBot', 'AxeSpam', 'WebMacro',
    'KillAura', 'CrystalAura', 'AnchorAura', 'AutoClicker'
)
$CheatRegex = [regex]::new(($CheatStrings | ForEach-Object { [regex]::Escape($_) }) -join '|')
# A class named exactly like a cheat module, e.g. AutoTotem.class or TriggerBotModule.class.
$CheatClassRegex = [regex]::new('^(?:' + (($CheatStrings | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?:Module|Hack|Feature|Mod)?$')

# Weak names: also ordinary game-code words (getVelocity, renderHitboxes, controller
# aim assist...). They only count when they are a whole name on their own: a class
# file called Velocity.class / VelocityModule.class, or the exact text "Velocity"
# stored as its own string in a class file - which is how cheat module names look.
$WeakCheatStrings = @('Velocity', 'Hitboxes', 'AimAssist', 'AutoArmor', 'FastPlace')
$weakAlt = ($WeakCheatStrings | ForEach-Object { [regex]::Escape($_) }) -join '|'
$WeakNameRegex = [regex]::new("(?:^|/)($weakAlt)(?:Module|Hack|Feature|Mod)?(?:\$[^/]*)?\.class$")
# CONSTANT_Utf8 entry in a class file: tag 0x01, 2-byte length, then the text.
$WeakConstRegex = [regex]::new('\x01\x00(?:' + (($WeakCheatStrings | ForEach-Object { [regex]::Escape([string][char]$_.Length) + [regex]::Escape($_) }) -join '|') + ')(?![\w])')

# Mods known to be safe even though their code contains a cheat-like name (for example a
# HUD that shows "AutoTotem" status). Matched by exact SHA1 so a renamed cheat can't
# pretend to be one of them. Add entries as  'sha1-in-lowercase' = 'Name'
# (the SHA1 is printed under every [CHEAT] result).
$TrustedMods = @{
    '1807bd0592525fe40d0d0ee69d30b7486c48fdc7' = 'FastClient HUD 1.21.11'   # contains Hitboxes/Velocity HUD names
    '34911f6d85906b40ca45e7750c65b713955451d2' = 'Dawn Client'              # contains Hitboxes/Velocity HUD names
}

# Extra trusted mods are also read from this file in the GitHub repo, so new
# versions can be added by editing trusted.txt on GitHub (no script change needed).
$TrustedListUrl = 'https://raw.githubusercontent.com/RyftTiers/ModAnzer/main/trusted.txt'

# Cheats and PvP macros that are published on Modrinth (or Megabase/CurseForge) still count
# as cheats. A known mod is flagged when:
#  - its Modrinth slug or SHA1 is listed in flagged.txt in the GitHub repo (edit it on GitHub,
#    no script change needed), or
#  - its name says what it does (FlaggedNameRegex: "AutoTotem", "Crystal Macro"...), or
#  - its jar has a class named like a cheat module (AutoTotem.class, TriggerBot.class...).
$FlaggedListUrl = 'https://raw.githubusercontent.com/RyftTiers/ModAnzer/main/flagged.txt'
$FlaggedNameRegex = [regex]::new('(?ix) \bmacros?\b | auto[\s_-]?(totem|crystal|anchor|pot|clicker|click|hit|double[\s_-]?hand|shield[\s_-]?break) | trigger[\s_-]?bot | (crystal|anchor|kill)[\s_-]?aura | aim[\s_-]?(assist|bot|lock) | (inventory|legit|hover)[\s_-]?totem | jump[\s_-]?reset | ping[\s_-]?spoof | axe[\s_-]?spam | web[\s_-]?macro | self[\s_-]?destruct')

# CurseForge lookups go through ModAnzer's small server, which keeps the CurseForge
# API key private (source: supabase/functions/modanzer-cf in the repo). Only CurseForge
# file fingerprints (numbers) are sent.
$CurseForgeProxyUrl = 'https://reumqqmnuvabnpmbstnu.supabase.co/functions/v1/modanzer-cf'

# Optional: your own CurseForge API key (free at https://console.curseforge.com) to ask
# CurseForge directly instead. Can also be set with the MODANZER_CF_KEY environment variable.
$CurseForgeApiKey = ''

# Screenshare reports: when the scan ends the player can press Enter to send the results.
# ModAnzer's server (source: supabase/functions/modanzer-report) saves them and sends back a
# short code. The player gives the code to staff, who run /ssresult in the Discord bot.
$ReportServerName = 'RyftTiers'
$ReportUrl = 'https://flifswwrhevzjwwhqitc.supabase.co/functions/v1/modanzer-report'
$script:RunReport = [ordered]@{ Mods = $null; System = $null; Injection = $null; Accounts = @() }

# Legit client files that contain common words like "Velocity" for their own features.
# A matching file (name AND folder) with ONLY common words counts as OK; any clear cheat
# name (KillAura, AutoCrystal...) still makes it a cheat.
$KnownClientJars = @(
    @{ Name = 'Dawn client'; File = '^dawn-client.*\.jar$'; Folder = '[\\/]\.(dawn|feather)[\\/]' }
)

function Get-KnownClient($file) {
    foreach ($k in $KnownClientJars) {
        if ($file.Name -match $k.File -and $file.FullName -match $k.Folder) { return $k.Name }
    }
    return $null
}

# Folder names that hold mods
$ModFolderNames = @('mods', 'user-mods')

# Dot-folders that are never Minecraft and are expensive to walk
$SkipDirs = @(
    '.git', '.gradle', '.m2', '.npm', '.nuget', '.cargo', '.rustup', '.android',
    '.vscode', '.vscode-server', '.cache', '.docker', '.conda', '.ipython',
    '.dotnet', '.templateengine', 'node_modules', 'assets', 'libraries',
    'versions', 'logs', 'crash-reports', 'screenshots', 'saves', 'resourcepacks',
    'shaderpacks', 'natives', 'jre', 'runtime', 'java'
)

$MaxDepth       = 6          # how deep to look for a mods folder under each root
$MaxEntryBytes  = 8MB        # skip unusually large entries inside a jar
$UserAgent      = 'ModAnzer (github.com/RyftTiers/ModAnzer)'

# ---------------------------------------------------------------- helpers

function Write-Section($text) {
    Write-Host "{ $text }" -ForegroundColor DarkCyan
}

function Get-ShortPath([string]$p) {
    foreach ($pair in @(@($env:APPDATA, '%APPDATA%'), @($env:LOCALAPPDATA, '%LOCALAPPDATA%'), @($env:USERPROFILE, '~'))) {
        if ($pair[0] -and $p.StartsWith($pair[0], [StringComparison]::OrdinalIgnoreCase)) {
            return $pair[1] + $p.Substring($pair[0].Length)
        }
    }
    return $p
}

function Get-LauncherName([string]$p) {
    $l = $p.Replace('/', '\').ToLowerInvariant()
    switch -Regex ($l) {
        'curseforge|\\twitch\\'      { return 'CurseForge' }
        'modrinthapp|theseus'        { return 'Modrinth' }
        'prismlauncher'              { return 'Prism' }
        'polymc'                     { return 'PolyMC' }
        'multimc'                    { return 'MultiMC' }
        'atlauncher'                 { return 'ATLauncher' }
        'gdlauncher'                 { return 'GDLauncher' }
        '\\\.technic\\'              { return 'Technic' }
        '\\\.(dawn|feather)\\'       { return 'Dawn' }
        '\\\.lunarclient\\'          { return 'Lunar' }
        'fastclient'                 { return 'Fast Client' }
        '\\\.tlauncher\\'            { return 'TLauncher' }
        '\\\.minecraft\\'            { return 'Minecraft' }
        '\\\.([^\\]+)\\'             { return ".$($Matches[1])" }
    }
    return 'Custom'
}

# Walk a root looking for folders named mods / user-mods, without descending into junk.
function Find-ModFolders([string]$root, [int]$depth = 0) {
    if ($depth -gt $MaxDepth) { return }
    $children = $null
    try { $children = [IO.Directory]::GetDirectories($root) } catch { return }
    foreach ($dir in $children) {
        $name = [IO.Path]::GetFileName($dir)
        if ($ModFolderNames -contains $name.ToLowerInvariant()) {
            $dir
            continue
        }
        if ($SkipDirs -contains $name.ToLowerInvariant()) { continue }
        try {
            if (([IO.File]::GetAttributes($dir) -band [IO.FileAttributes]::ReparsePoint)) { continue }
        } catch { continue }
        Find-ModFolders $dir ($depth + 1)
    }
}

# Game directories of any Minecraft that is running right now (--gameDir argument).
function Get-RunningGameDirs {
    $result = @()
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -ErrorAction Stop
    } catch { return $result }
    foreach ($p in $procs) {
        if ($p.CommandLine -match '--gameDir\s+(?:"([^"]+)"|(\S+))') {
            $dir = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
            $result += [PSCustomObject]@{ Pid = $p.ProcessId; Dir = $dir; Started = $p.CreationDate }
        }
    }
    return $result
}

function Get-ZoneIdentifier([string]$filePath) {
    try {
        $ads = Get-Content -Raw -Stream Zone.Identifier -LiteralPath $filePath -ErrorAction Stop
        if ($ads -match 'HostUrl=(.+)') { return $Matches[1].Trim() }
    } catch {}
    return $null
}

function Read-EntryBytes([System.IO.Compression.ZipArchiveEntry]$entry) {
    $ms = New-Object IO.MemoryStream
    $s = $entry.Open()
    try { $s.CopyTo($ms) } finally { $s.Dispose() }
    return $ms.ToArray()
}

# Search a jar (from a stream) for cheat strings: entry names, then file contents, then nested jars.
function Search-Jar([IO.Stream]$stream, [string]$label, [System.Collections.Generic.List[object]]$hits, [int]$level = 0) {
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $zip = $null
    try { $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read, $true) }
    catch { return }
    try {
        $found = New-Object 'System.Collections.Generic.HashSet[string]'
        $weak = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($entry in $zip.Entries) {
            foreach ($m in $CheatRegex.Matches($entry.FullName)) { [void]$found.Add($m.Value) }
            $wm = $WeakNameRegex.Match($entry.FullName)
            if ($wm.Success) { [void]$weak.Add($wm.Groups[1].Value) }

            if ($entry.Length -eq 0 -or $entry.Length -gt $MaxEntryBytes) { continue }
            $lower = $entry.FullName.ToLowerInvariant()

            if ($lower.EndsWith('.jar') -and $level -lt 3) {
                $bytes = Read-EntryBytes $entry
                $inner = New-Object IO.MemoryStream(,$bytes)
                Search-Jar $inner "$label -> $([IO.Path]::GetFileName($entry.FullName))" $hits ($level + 1)
                $inner.Dispose()
                continue
            }
            if ($lower.EndsWith('.class') -or $lower.EndsWith('.json') -or $lower.EndsWith('.toml') -or $lower.EndsWith('.mf')) {
                $text = $latin1.GetString((Read-EntryBytes $entry))
                foreach ($m in $CheatRegex.Matches($text)) { [void]$found.Add($m.Value) }
                if ($lower.EndsWith('.class')) {
                    foreach ($m in $WeakConstRegex.Matches($text)) { [void]$weak.Add($m.Value.Substring(3)) }
                }
            }
        }
        if ($found.Count -gt 0 -or $weak.Count -gt 0) {
            $all = @(@($found) + @($weak) | Sort-Object -Unique)
            $hits.Add([PSCustomObject]@{ Where = $label; Strings = $all; Strong = ($found.Count -gt 0) })
        }
    } finally { $zip.Dispose() }
}

# CurseForge fingerprint: MurmurHash2 (seed 1) of the file with tab/LF/CR/space bytes removed.
function Get-CurseForgeFingerprint([string]$path) {
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $data = $latin1.GetBytes(($latin1.GetString([IO.File]::ReadAllBytes($path)) -replace "[\t\n\r ]", ''))
    $mask = [uint64]4294967295
    $m = [uint64]0x5bd1e995
    $len = $data.Length
    $h = ([uint64]1 -bxor [uint64]$len) -band $mask
    $i = 0
    while ($len - $i -ge 4) {
        $k = [uint64][BitConverter]::ToUInt32($data, $i)
        $k = ($k * $m) -band $mask
        $k = $k -bxor ($k -shr 24)
        $k = ($k * $m) -band $mask
        $h = (($h * $m) -band $mask) -bxor $k
        $i += 4
    }
    $rest = $len - $i
    if ($rest -ge 3) { $h = $h -bxor ([uint64]$data[$i + 2] -shl 16) }
    if ($rest -ge 2) { $h = $h -bxor ([uint64]$data[$i + 1] -shl 8) }
    if ($rest -ge 1) { $h = (($h -bxor [uint64]$data[$i]) * $m) -band $mask }
    $h = $h -bxor ($h -shr 13)
    $h = ($h * $m) -band $mask
    $h = $h -bxor ($h -shr 15)
    return [uint32]$h
}

# Mods the CurseForge app recorded as installed (minecraftinstance.json next to the mods folder).
function Get-CurseForgeRecords([string]$modsFolder) {
    $map = @{}
    $json = Join-Path (Split-Path -Parent $modsFolder) 'minecraftinstance.json'
    if (-not (Test-Path -LiteralPath $json)) { return $map }
    try {
        $inst = Get-Content -Raw -LiteralPath $json | ConvertFrom-Json
        foreach ($a in @($inst.installedAddons)) {
            $f = $a.installedFile
            if ($f -and $f.fileName -and $a.name) {
                $map[[string]$f.fileName] = [PSCustomObject]@{ Name = [string]$a.name; Length = $f.fileLength }
            }
        }
    } catch {}
    return $map
}

function Wait-BeforeClose {
    if (-not $NoPause) {
        Write-Host
        Read-Host 'Press Enter to close' | Out-Null
    }
}

function Invoke-Json([string]$uri, [string]$method = 'Get', $body = $null) {
    $params = @{ Uri = $uri; Method = $method; UseBasicParsing = $true; UserAgent = $UserAgent; TimeoutSec = 20 }
    if ($body) { $params.Body = $body; $params.ContentType = 'application/json' }
    return Invoke-RestMethod @params
}

# ---------------------------------------------------------------- 1. find folders

if ($Host.Name -eq 'ConsoleHost') { try { Clear-Host } catch {} }
Write-Host 'ModAnzer' -ForegroundColor Yellow -NoNewline
Write-Host '  - Minecraft screenshare tool (based on HabibiModAnalyzer by HadronCollision)' -ForegroundColor DarkGray
Write-Host

if (-not $SkipIntro) {
    Write-Host 'This is NOT a hacking or malware tool. It only READS, and only:' -ForegroundColor White
    Write-Host '  Mod Analyzer' -ForegroundColor White
    Write-Host '  - Finds your Minecraft mods folders and makes a fingerprint (SHA1) of each .jar' -ForegroundColor Gray
    Write-Host '  - Looks those fingerprints up on Modrinth, Megabase and CurseForge to name your mods' -ForegroundColor Gray
    Write-Host '  - Searches mods it does not recognise for known cheat names' -ForegroundColor Gray
    Write-Host '  Injection Checker' -ForegroundColor White
    Write-Host '  - Reads how the running Minecraft was started and which DLLs are loaded into it' -ForegroundColor Gray
    Write-Host '  - Reads Minecraft''s memory (read-only) for cheat names and hidden programs' -ForegroundColor Gray
    Write-Host '  - Watches the game, its mods folder and newly started programs while it runs' -ForegroundColor Gray
    Write-Host '  System Check' -ForegroundColor White
    Write-Host '  - Reads Windows records of programs that ran (BAM, Prefetch), cleared logs,' -ForegroundColor Gray
    Write-Host '    USB drives, PowerShell history, the Recycle Bin and recent downloads' -ForegroundColor Gray
    Write-Host '  - Lists Minecraft account NAMES used on this PC (never tokens or emails)' -ForegroundColor Gray
    Write-Host '  Everything is shown on this screen only. It may ask for administrator rights' -ForegroundColor Gray
    Write-Host '  so it can read those Windows records - you can say no.' -ForegroundColor Gray
    Write-Host
    Write-Host 'It does NOT:' -ForegroundColor White
    Write-Host '  - Upload your files. It sends mod fingerprints for the lookups and, ONLY when you' -ForegroundColor Gray
    Write-Host "    press Enter at the end, a summary of the results to $ReportServerName staff" -ForegroundColor Gray
    Write-Host '    (user folders shown as ~, Minecraft account names included)' -ForegroundColor Gray
    Write-Host '  - Read passwords, tokens, emails, browser data or Discord' -ForegroundColor Gray
    Write-Host '  - Change the game''s memory, or inject into or interfere with any program' -ForegroundColor Gray
    Write-Host '  - Change, move or delete any files, or change any settings' -ForegroundColor Gray
    Write-Host '  - Install anything or keep running after you close it' -ForegroundColor Gray
    Write-Host
    Write-Host 'Source code: https://github.com/RyftTiers/ModAnzer' -ForegroundColor DarkGray
    Write-Host
    Read-Host 'Press Enter to start (or Ctrl+C to quit)' | Out-Null
    Write-Host
}

# ---------------------------------------------------------------- injection checker

function Get-MinecraftProcesses {
    $list = @()
    $cim = $null
    try { $cim = @(Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -ErrorAction Stop) } catch {}
    if ($null -ne $cim) {
        foreach ($p in $cim) {
            $list += [PSCustomObject]@{ Pid = [int]$p.ProcessId; Path = [string]$p.ExecutablePath; CommandLine = [string]$p.CommandLine; Started = $p.CreationDate }
        }
    } else {
        foreach ($p in @(Get-Process -Name 'javaw', 'java' -ErrorAction SilentlyContinue)) {
            $list += [PSCustomObject]@{ Pid = $p.Id; Path = [string]$p.Path; CommandLine = [string]$p.CommandLine; Started = $p.StartTime }
        }
    }
    return @($list | Where-Object { $_.CommandLine -match 'minecraft|fabric|forge|quilt|lunar|feather|dawn|--gameDir|--accessToken' })
}

function Get-ProcessModuleFiles([int]$procId) {
    try {
        $p = Get-Process -Id $procId -ErrorAction Stop
        return @($p.Modules | ForEach-Object { $_.FileName } | Where-Object { $_ } | Select-Object -Unique)
    } catch { return $null }
}

$script:SignerCache = @{}
function Get-Signer([string]$file) {
    if ($script:SignerCache.ContainsKey($file)) { return $script:SignerCache[$file] }
    $r = $null
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction Stop
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
            $r = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        }
    } catch {}
    $script:SignerCache[$file] = $r
    return $r
}

function Test-UnderPath([string]$file, [string[]]$roots) {
    foreach ($r in $roots) {
        if ($r -and $file.StartsWith($r.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Folders that normal programs aren't run or loaded from
function Get-UserDropFolders {
    $h = $env:USERPROFILE
    return @("$h\Downloads", "$h\Desktop", "$h\Documents", $env:TEMP, "$env:LOCALAPPDATA\Temp", "$h\Videos", "$h\Music", "$h\Pictures") |
        Where-Object { $_ } | ForEach-Object { $_.Replace('\', [IO.Path]::DirectorySeparatorChar) } | Select-Object -Unique
}

# Classify one DLL loaded into Minecraft. Returns $null when it's a normal Windows/Java/game file.
function Get-ModuleVerdict([string]$file, [string]$javaHome) {
    if (-not [IO.Path]::IsPathRooted($file)) { return $null }
    $name = [IO.Path]::GetFileName($file).ToLowerInvariant()
    if ($name -match '^(lib)?instrument\.(dll|so|dylib)$') {
        return [PSCustomObject]@{ Level = 'Red'; Text = 'Java agent support (instrument) is loaded - a Java agent was added at launch or attached to the running game' }
    }
    if ($name -match '^(lib)?jdwp\.(dll|so|dylib)$') {
        return [PSCustomObject]@{ Level = 'Red'; Text = 'Java debugger (JDWP) is loaded - lets other programs change the game while it runs' }
    }
    $sysRoots = @($env:SystemRoot, $env:windir, ${env:ProgramFiles}, ${env:ProgramFiles(x86)}, $javaHome, '/usr/lib', '/lib', '/usr/lib64', '/lib64')
    $drop = Get-UserDropFolders
    $inDrop = Test-UnderPath $file $drop
    # LWJGL / game natives that Minecraft itself unpacks (often into Temp)
    $isGameNative = ($name -match '^(lib)?(lwjgl|glfw|openal|jemalloc|jinput|jnidispatch|sqlite|discord[-_]?(rpc|game-sdk)|flite|tinyfd|stb|opengl|opus|rnnoise|speex|lame|vosk)') -and
                    ($file -match '[\\/](lwjgl|natives|bin|\.minecraft|jna|versions|libraries|voicechat|opus)[^\\/]*[\\/]' -or $file -match 'lwjgl|jna|voicechat')
    if ($isGameNative) { return $null }
    if ((Test-UnderPath $file $sysRoots) -and -not $inDrop) { return $null }

    $signer = Get-Signer $file
    if ($inDrop) {
        $where = if ($signer) { "signed by $signer" } else { 'not signed' }
        return [PSCustomObject]@{ Level = 'Red'; Text = "loaded from a user folder ($where)" }
    }
    if (-not $signer) { return [PSCustomObject]@{ Level = 'Red'; Text = 'not signed by any publisher' } }
    return [PSCustomObject]@{ Level = 'Yellow'; Text = "signed by $signer (overlays like Discord, OBS, NVIDIA or Steam look like this)" }
}

function Get-LaunchFlags([string]$cmd) {
    $flags = @()
    foreach ($m in [regex]::Matches($cmd, '-javaagent:(?:"([^"]+)"|(\S+))')) {
        $v = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        $flags += "Java agent at launch: $v   (normal for Lunar's own agents, suspicious otherwise)"
    }
    foreach ($m in [regex]::Matches($cmd, '-(agentpath|agentlib):(?:"([^"]+)"|(\S+))')) {
        $v = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { $m.Groups[3].Value }
        $flags += "Native agent at launch (-$($m.Groups[1].Value)): $v"
    }
    foreach ($m in [regex]::Matches($cmd, '-D(fabric\.addMods|fabric\.loadMods|fml\.coreMods\.load|fml\.modFolders|forge\.mods|fml\.mods)=(?:"([^"]+)"|(\S+))')) {
        $v = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { $m.Groups[3].Value }
        $flags += "Extra mods loaded from outside the mods folder (-D$($m.Groups[1].Value)): $v"
    }
    if ($cmd -match '-Xrunjdwp|-Xdebug') { $flags += 'Started with the Java debugger turned on (-Xdebug / -Xrunjdwp)' }
    if ($cmd -match '(^|\s)(-noverify|-Xverify:none)(\s|$)') { $flags += 'Bytecode verifier turned off (-noverify) - often needed by injected clients' }
    return $flags
}

function Get-GameDirFromCommand([string]$cmd) {
    if ($cmd -match '--gameDir\s+(?:"([^"]+)"|(\S+))') { if ($Matches[1]) { return $Matches[1] } else { return $Matches[2] } }
    return $null
}

function Get-ModJarSet([string]$gameDir) {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($gameDir) {
        $mods = Join-Path $gameDir 'mods'
        if (Test-Path -LiteralPath $mods) {
            Get-ChildItem -LiteralPath $mods -Filter *.jar -File -Recurse -Depth 1 -ErrorAction SilentlyContinue | ForEach-Object { [void]$set.Add($_.FullName) }
        }
    }
    return ,$set
}

function Write-Alert([string]$level, [string]$text, $alerts) {
    $color = switch ($level) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } default { 'Gray' } }
    $stamp = (Get-Date).ToString('HH:mm:ss')
    Write-Host "`r$(' ' * 100)`r" -NoNewline
    Write-Host "  [$stamp] " -ForegroundColor DarkGray -NoNewline
    Write-Host $text -ForegroundColor $color
    if ($null -ne $alerts) { $alerts.Add([PSCustomObject]@{ Time = $stamp; Level = $level; Text = $text }) }
}

function Start-InjectionChecker {
    Write-Section 'Injection Checker'
    $procs = @(Get-MinecraftProcesses)
    while ($procs.Count -eq 0) {
        if ($NoPause) {
            Write-Host 'No running Minecraft found. Start the game, then run the Injection Checker again.' -ForegroundColor Red
            return
        }
        $in = Read-Host 'No running Minecraft found. Start the game, then press Enter to look again (Q to quit)'
        if ($in -match '^\s*[qQ]') { return }
        $procs = @(Get-MinecraftProcesses)
    }
    $p = $procs[0]
    if ($procs.Count -gt 1) {
        for ($n = 0; $n -lt $procs.Count; $n++) {
            $gd = Get-GameDirFromCommand $procs[$n].CommandLine
            Write-Host ('  {0}) PID {1}  {2}' -f ($n + 1), $procs[$n].Pid, $(if ($gd) { Get-ShortPath $gd } else { '' }))
        }
        $pick = 0
        if ($NoPause) { $pick = 1; Write-Host '  Checking the first one.' -ForegroundColor DarkGray }
        while ($pick -lt 1 -or $pick -gt $procs.Count) { [void][int]::TryParse((Read-Host "Which Minecraft? 1-$($procs.Count)"), [ref]$pick) }
        $p = $procs[$pick - 1]
    }

    $gameDir = Get-GameDirFromCommand $p.CommandLine
    $javaHome = if ($p.Path) { Split-Path -Parent (Split-Path -Parent $p.Path) } else { $null }
    $up = ''
    if ($p.Started) { $t = (Get-Date) - $p.Started; $up = ' - up {0}h {1}m {2}s' -f [int][math]::Floor($t.TotalHours), $t.Minutes, $t.Seconds }
    Write-Host "> Minecraft PID $($p.Pid)$up" -ForegroundColor White
    if ($gameDir) { Write-Host "  game folder: $(Get-ShortPath $gameDir)" -ForegroundColor Gray }
    if ($p.Path)  { Write-Host "  java: $(Get-ShortPath $p.Path)" -ForegroundColor Gray }
    Write-Host

    $alerts = New-Object 'System.Collections.Generic.List[object]'

    # 1. launch options
    Write-Section 'Launch options'
    $flags = @(Get-LaunchFlags $p.CommandLine)
    if ($flags.Count -eq 0) { Write-Host '  Nothing unusual.' -ForegroundColor Green }
    foreach ($f in $flags) { Write-Alert 'Red' $f $alerts }
    Write-Host

    # 2. DLLs loaded right now
    Write-Section 'Loaded DLLs'
    $baseline = Get-ProcessModuleFiles $p.Pid
    if ($null -eq $baseline) {
        Write-Host '  Could not read the loaded DLLs (the game may be running as administrator - run this as administrator too).' -ForegroundColor Red
        $baseline = @()
    } else {
        Write-Host "  $($baseline.Count) loaded. Checking..." -ForegroundColor DarkGray
        $odd = 0
        foreach ($m in $baseline) {
            $v = Get-ModuleVerdict $m $javaHome
            if ($v) { $odd++; Write-Alert $v.Level "$(Get-ShortPath $m) - $($v.Text)" $alerts }
        }
        if ($odd -eq 0) { Write-Host '  All are normal Windows, Java or game files.' -ForegroundColor Green }
    }
    Write-Host

    # 3. game memory
    Write-Section 'Game memory'
    if (-not $IsWindowsOS) {
        Write-Host '  Skipped - only works on Windows.' -ForegroundColor DarkGray
    } elseif (-not (Initialize-Native)) {
        Write-Host '  Skipped - could not load the memory reader (antivirus may have blocked it).' -ForegroundColor Yellow
    } else {
        Write-Host '  Reading Minecraft''s memory (read-only) for cheat names and hidden programs. This can take a minute...' -ForegroundColor DarkGray
        $scan = [ModAnzerNative]::Scan($p.Pid, [string[]]$MemoryNeedles, 8GB)
        if ($scan.Error) {
            Write-Host "  Could not read the game's memory: $($scan.Error). Run ModAnzer as administrator." -ForegroundColor Red
        } else {
            Write-Host ('  Scanned {0:N1} GB in {1} regions{2}.' -f ($scan.BytesScanned / 1GB), $scan.Regions, $(if ($scan.Truncated) { ' (stopped at the 8 GB limit)' })) -ForegroundColor DarkGray
            foreach ($img in $scan.HiddenImages) {
                Write-Alert 'Red' "Hidden program in Minecraft's memory at $img - a DLL/EXE with no file behind it (how manual-mapped cheats hide)" $alerts
            }
            foreach ($k in ($scan.Hits.Keys | Sort-Object)) {
                Write-Alert 'Red' "Cheat name in Minecraft's memory: $k ($($scan.Hits[$k]) times)" $alerts
            }
            if ($scan.HiddenImages.Count -eq 0 -and $scan.Hits.Count -eq 0) { Write-Host '  Nothing found.' -ForegroundColor Green }
            elseif ($scan.Hits.Count -gt 0) { Write-Host '  Note: a name can also be in memory because it was typed or shown in chat - check the context.' -ForegroundColor DarkGray }
        }
    }
    Write-Host

    # 4. live watch
    Write-Section 'Live watch'
    Write-Host '  Watching for anything injected into the game, mods added or removed, and new programs' -ForegroundColor Gray
    Write-Host '  started from Downloads/Desktop/Temp. Keep this window open during the fight.' -ForegroundColor Gray
    if ($LiveSeconds -le 0 -and -not $StopFile) { Write-Host '  Press Q to stop.' -ForegroundColor Yellow }
    Write-Host

    $known = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($m in $baseline) { [void]$known.Add($m) }
    $jarsNow = Get-ModJarSet $gameDir
    $seenProcs = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($x in (Get-Process -ErrorAction SilentlyContinue)) { [void]$seenProcs.Add($x.Id) }
    $drop = Get-UserDropFolders
    $start = Get-Date
    $canReadKeys = $true
    $liveAlerts = 0

    while ($true) {
        $elapsed = (Get-Date) - $start
        if ($LiveSeconds -gt 0 -and $elapsed.TotalSeconds -ge $LiveSeconds) { break }
        if ($StopFile -and (Test-Path -LiteralPath $StopFile)) { break }
        if ($canReadKeys) {
            try {
                if ([Console]::KeyAvailable) {
                    $k = [Console]::ReadKey($true)
                    if ($k.Key -eq 'Q' -or $k.Key -eq 'Escape') { break }
                }
            } catch { $canReadKeys = $false }
        }

        if (-not (Get-Process -Id $p.Pid -ErrorAction SilentlyContinue)) {
            Write-Alert 'Yellow' 'Minecraft was closed.' $alerts; $liveAlerts++
            break
        }

        $now = Get-ProcessModuleFiles $p.Pid
        if ($null -ne $now) {
            $nowSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($m in $now) {
                [void]$nowSet.Add($m)
                if ($known.Add($m)) {
                    $v = Get-ModuleVerdict $m $javaHome
                    if ($v) { Write-Alert $v.Level "NEW DLL injected/loaded: $(Get-ShortPath $m) - $($v.Text)" $alerts; $liveAlerts++ }
                    else { Write-Alert 'Gray' "New DLL loaded: $(Get-ShortPath $m) (normal file)" $null }
                }
            }
            foreach ($m in @($known)) {
                if (-not $nowSet.Contains($m) -and (Get-ModuleVerdict $m $javaHome)) {
                    Write-Alert 'Yellow' "DLL unloaded: $(Get-ShortPath $m) (injectors sometimes unload to hide)" $alerts; $liveAlerts++
                    [void]$known.Remove($m)
                }
            }
        }

        $jarsNew = Get-ModJarSet $gameDir
        foreach ($j in $jarsNew) { if (-not $jarsNow.Contains($j)) { Write-Alert 'Red' "Mod ADDED while the game is running: $(Get-ShortPath $j)" $alerts; $liveAlerts++ } }
        foreach ($j in $jarsNow) { if (-not $jarsNew.Contains($j)) { Write-Alert 'Red' "Mod REMOVED while the game is running: $(Get-ShortPath $j)" $alerts; $liveAlerts++ } }
        $jarsNow = $jarsNew

        foreach ($x in (Get-Process -ErrorAction SilentlyContinue)) {
            if ($seenProcs.Add($x.Id)) {
                $xp = $null
                try { $xp = $x.Path } catch {}
                if ($xp -and (Test-UnderPath $xp $drop)) {
                    Write-Alert 'Red' "Program started from a user folder: $(Get-ShortPath $xp) (PID $($x.Id))" $alerts; $liveAlerts++
                }
            }
        }

        $status = '  Watching PID {0} - {1:hh\:mm\:ss} - live alerts: {2}' -f $p.Pid, $elapsed, $liveAlerts
        Write-Host "`r$status   " -ForegroundColor DarkCyan -NoNewline
        Start-Sleep -Milliseconds 1500
    }
    Write-Host "`r$(' ' * 100)`r" -NoNewline
    Write-Host

    $script:RunReport.Injection = [ordered]@{
        Admin = (Test-Admin); Uptime = $up.TrimStart(' -'); GameFolder = $(if ($gameDir) { Get-ShortPath $gameDir } else { '' })
        Alerts = @($alerts | ForEach-Object { [ordered]@{ Time = $_.Time; Level = $_.Level; Text = $_.Text } })
    }
    Write-Section 'Injection Checker summary'
    $red = @($alerts | Where-Object { $_.Level -eq 'Red' })
    $yellow = @($alerts | Where-Object { $_.Level -eq 'Yellow' })
    if ($alerts.Count -eq 0) {
        Write-Host '  Nothing suspicious found.' -ForegroundColor Green
    } else {
        Write-Host "  Suspicious: $($red.Count)" -ForegroundColor $(if ($red.Count) { 'Red' } else { 'Gray' })
        Write-Host "  Worth a look: $($yellow.Count)" -ForegroundColor $(if ($yellow.Count) { 'Yellow' } else { 'Gray' })
        Write-Host
        foreach ($a in $alerts) {
            Write-Host "  [$($a.Time)] " -ForegroundColor DarkGray -NoNewline
            Write-Host $a.Text -ForegroundColor $(if ($a.Level -eq 'Red') { 'Red' } else { 'Yellow' })
        }
    }
    Write-Host
    Write-Host 'This catches injected DLLs, Java agents, swapped mods and many memory-only cheats. Kernel-level cheats,' -ForegroundColor DarkGray
    Write-Host 'or cheats that wipe their headers and strings, can still hide. Alerts are leads - check them by hand.' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- native helper
# Used only by the System Check (BAM path names) and the Injection Checker's memory
# scan, and only compiled when one of those runs. It only READS: it opens Minecraft
# with query + read rights, walks its memory regions and reads them. It never writes
# to, suspends or injects into any process.

$NativeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class ModAnzerNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct MBI {
        public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
        public ushort PartitionId; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
    }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI info, IntPtr len);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint QueryDosDeviceW(string device, StringBuilder target, uint max);

    public static string DosDevice(string drive) {
        StringBuilder sb = new StringBuilder(1024);
        return QueryDosDeviceW(drive, sb, 1024) == 0 ? null : sb.ToString();
    }

    public class ScanResult {
        public long BytesScanned; public int Regions; public bool Truncated; public string Error;
        public Dictionary<string, long> Hits = new Dictionary<string, long>();
        public List<string> HiddenImages = new List<string>();
    }

    const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;
    const uint MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000, PAGE_NOACCESS = 0x01, PAGE_GUARD = 0x100;

    static void BuildPatterns(string[] needles, out List<byte[]> pats, out List<string> names, out List<int>[] byFirst, out int maxLen) {
        pats = new List<byte[]>(); names = new List<string>();
        foreach (string n in needles) {
            pats.Add(Encoding.ASCII.GetBytes(n)); names.Add(n);
            pats.Add(Encoding.Unicode.GetBytes(n)); names.Add(n);
        }
        byFirst = new List<int>[256];
        maxLen = 1;
        for (int i = 0; i < pats.Count; i++) {
            int f = pats[i][0];
            if (byFirst[f] == null) byFirst[f] = new List<int>();
            byFirst[f].Add(i);
            if (pats[i].Length > maxLen) maxLen = pats[i].Length;
        }
    }

    static void CountMatches(byte[] buf, int n, List<byte[]> pats, List<string> names, List<int>[] byFirst, Dictionary<string, long> hits) {
        for (int i = 0; i < n; i++) {
            List<int> cand = byFirst[buf[i]];
            if (cand == null) continue;
            foreach (int k in cand) {
                byte[] p = pats[k];
                if (i + p.Length > n) continue;
                int j = 1;
                while (j < p.Length && buf[i + j] == p[j]) j++;
                if (j == p.Length) { long c; hits.TryGetValue(names[k], out c); hits[names[k]] = c + 1; }
            }
        }
    }

    // "MZ" header that points to a "PE\0\0" signature: the start of a Windows program image.
    public static bool IsPeHeader(byte[] hdr, int len) {
        if (len < 0x40 || hdr[0] != 0x4D || hdr[1] != 0x5A) return false;
        int lfanew = BitConverter.ToInt32(hdr, 0x3C);
        return lfanew > 0 && lfanew + 4 <= len && hdr[lfanew] == 0x50 && hdr[lfanew + 1] == 0x45 && hdr[lfanew + 2] == 0 && hdr[lfanew + 3] == 0;
    }

    // Same matching as Scan, on a buffer instead of a process (used for testing).
    public static Dictionary<string, long> FindInBuffer(byte[] data, string[] needles) {
        List<byte[]> pats; List<string> names; List<int>[] byFirst; int maxLen;
        BuildPatterns(needles, out pats, out names, out byFirst, out maxLen);
        Dictionary<string, long> hits = new Dictionary<string, long>();
        CountMatches(data, data.Length, pats, names, byFirst, hits);
        return hits;
    }

    public static ScanResult Scan(int pid, string[] needles, long maxBytes) {
        ScanResult res = new ScanResult();
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) { res.Error = "could not open the game for reading (Windows error " + Marshal.GetLastWin32Error() + ")"; return res; }
        try {
            List<byte[]> pats; List<string> names; List<int>[] byFirst; int maxLen;
            BuildPatterns(needles, out pats, out names, out byFirst, out maxLen);
            const int CHUNK = 4 * 1024 * 1024;
            byte[] buf = new byte[CHUNK];
            byte[] hdr = new byte[1024];
            IntPtr mbiSize = (IntPtr)Marshal.SizeOf(typeof(MBI));
            long addr = 0;
            MBI m;
            while (VirtualQueryEx(h, (IntPtr)addr, out m, mbiSize) != IntPtr.Zero) {
                long baseA = m.BaseAddress.ToInt64(), size = m.RegionSize.ToInt64();
                if (size <= 0) break;
                bool readable = m.State == MEM_COMMIT && m.Protect != 0 && (m.Protect & PAGE_NOACCESS) == 0 && (m.Protect & PAGE_GUARD) == 0;
                if (readable) {
                    res.Regions++;
                    IntPtr got;
                    // A complete program (DLL/EXE) sitting in private memory with no file behind it.
                    if (m.Type == MEM_PRIVATE && baseA == m.AllocationBase.ToInt64() &&
                        ReadProcessMemory(h, (IntPtr)baseA, hdr, (IntPtr)hdr.Length, out got) && IsPeHeader(hdr, (int)got.ToInt64())) {
                        bool exec = (m.Protect & 0xF0) != 0;
                        res.HiddenImages.Add(string.Format("0x{0:X} ({1} KB{2})", baseA, size / 1024, exec ? ", executable" : ""));
                    }
                    long off = 0;
                    while (off < size) {
                        if (res.BytesScanned >= maxBytes) { res.Truncated = true; break; }
                        int want = (int)Math.Min(CHUNK, size - off);
                        if (!ReadProcessMemory(h, (IntPtr)(baseA + off), buf, (IntPtr)want, out got) || got.ToInt64() <= 0) { off += want; continue; }
                        int n = (int)got.ToInt64();
                        res.BytesScanned += n;
                        CountMatches(buf, n, pats, names, byFirst, res.Hits);
                        if (off + want >= size) break;
                        off += want - (maxLen - 1);
                    }
                    if (res.Truncated) break;
                }
                long next = baseA + size;
                if (next <= addr) break;
                addr = next;
            }
        } finally { CloseHandle(h); }
        return res;
    }
}
'@

$IsWindowsOS = ($env:OS -eq 'Windows_NT')

function Initialize-Native {
    if (-not $IsWindowsOS) { return $false }
    if ('ModAnzerNative' -as [type]) { return $true }
    try { Add-Type -TypeDefinition $NativeSource -Language CSharp -ErrorAction Stop; return $true } catch { return $false }
}

function Test-Admin {
    if (-not $IsWindowsOS) { return $false }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# Names in Minecraft memory or process lists that point to cheats.
$MemoryNeedles = @($CheatStrings) + @('meteordevelopment', 'wurstclient', 'net/ccbluex', 'aristois', 'rusherhack', 'thunderhack', 'impactclient', 'doomsdayclient')

# Program names that point to cheating tools (red) or are worth a look (yellow).
$ToolRedRe    = 'cheat\s?engine|process\s?hacker|system\s?informer|x64dbg|x32dbg|ollydbg|dnspy|recaf|jd-gui|bytecode\s?viewer|extreme\s?injector|xenos|injector|dll\s?inject|kdmapper|manual\s?map|vape[ .\-_]?(lite|v4|client)?\.exe|doomsday'
$ToolYellowRe = 'autohotkey|\.ahk$|tinytask|macro|procexp|process\s?explorer|ghidra|ida64|ida\.exe|wireshark|fiddler|cheat'

function Get-ToolLevel([string]$name) {
    if (-not $name) { return $null }
    $n = $name.ToLowerInvariant()
    if ($n -match $ToolRedRe) { return 'Red' }
    if ($n -match $ToolYellowRe) { return 'Yellow' }
    return $null
}

# ---------------------------------------------------------------- system check

function Write-CheckSummary([string]$title, $alerts) {
    Write-Section $title
    $red = @($alerts | Where-Object { $_.Level -eq 'Red' })
    $yellow = @($alerts | Where-Object { $_.Level -eq 'Yellow' })
    if ($red.Count -eq 0 -and $yellow.Count -eq 0) {
        Write-Host '  Nothing suspicious found.' -ForegroundColor Green
        return
    }
    Write-Host "  Suspicious: $($red.Count)" -ForegroundColor $(if ($red.Count) { 'Red' } else { 'Gray' })
    Write-Host "  Worth a look: $($yellow.Count)" -ForegroundColor $(if ($yellow.Count) { 'Yellow' } else { 'Gray' })
    Write-Host
    foreach ($a in @($red) + @($yellow)) {
        Write-Host "  [$($a.Time)] " -ForegroundColor DarkGray -NoNewline
        Write-Host $a.Text -ForegroundColor $(if ($a.Level -eq 'Red') { 'Red' } else { 'Yellow' })
    }
}

function Get-ProfileNames($obj, $into) {
    if ($null -eq $obj) { return }
    if ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string]) { foreach ($x in $obj) { Get-ProfileNames $x $into }; return }
    if ($obj -isnot [PSCustomObject]) { return }
    foreach ($prop in $obj.PSObject.Properties) {
        if ($prop.Name -in @('minecraftProfile', 'profile') -and $prop.Value -is [PSCustomObject] -and $prop.Value.name -is [string]) {
            [void]$into.Add($prop.Value.name)
        } elseif ($prop.Value -is [PSCustomObject] -or ($prop.Value -is [System.Collections.IEnumerable] -and $prop.Value -isnot [string])) {
            Get-ProfileNames $prop.Value $into
        }
    }
}

# Minecraft account NAMES from launcher files and game logs (never tokens or emails).
function Get-MinecraftAccountNames {
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $acctFiles = @(
        "$env:APPDATA\.minecraft\launcher_accounts.json",
        "$env:APPDATA\.minecraft\launcher_accounts_microsoft_store.json",
        "$env:APPDATA\PrismLauncher\accounts.json",
        "$env:APPDATA\PolyMC\accounts.json",
        "$env:USERPROFILE\.lunarclient\settings\game\accounts.json"
    )
    foreach ($af in $acctFiles) {
        if (-not (Test-Path -LiteralPath $af)) { continue }
        try { Get-ProfileNames (Get-Content -Raw -LiteralPath $af | ConvertFrom-Json) $names } catch {}
    }
    $logGlobs = @(
        "$env:APPDATA\.minecraft\logs\latest.log",
        "$env:APPDATA\ModrinthApp\profiles\*\logs\latest.log",
        "$env:APPDATA\PrismLauncher\instances\*\.minecraft\logs\latest.log",
        "$env:USERPROFILE\curseforge\minecraft\Instances\*\logs\latest.log",
        "$env:APPDATA\.dawn\*\logs\latest.log",
        "$env:USERPROFILE\.lunarclient\logs\game\*.log"
    )
    foreach ($g in $logGlobs) {
        foreach ($lf in @(Get-ChildItem -Path $g -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10)) {
            try {
                $fs = [IO.File]::Open($lf.FullName, 'Open', 'Read', 'ReadWrite')
                try {
                    $len = [math]::Min($fs.Length, 2MB)
                    $buf = New-Object byte[] $len
                    [void]$fs.Read($buf, 0, $len)
                    foreach ($m in [regex]::Matches([Text.Encoding]::UTF8.GetString($buf), 'Setting user:\s*([A-Za-z0-9_]{3,16})')) { [void]$names.Add($m.Groups[1].Value) }
                } finally { $fs.Dispose() }
            } catch {}
        }
    }
    return ,$names
}

function Invoke-SystemCheck {
    Write-Section 'System Check'
    if (-not $IsWindowsOS) { Write-Host '  The System Check only works on Windows.' -ForegroundColor Red; return }
    $admin = Test-Admin
    if (-not $admin) { Write-Host '  Not running as administrator: execution history, prefetch and some logs will be skipped.' -ForegroundColor Yellow }
    $alerts = New-Object 'System.Collections.Generic.List[object]'
    $now = Get-Date
    $day = $now.AddHours(-24)
    $week = $now.AddDays(-7)
    $drop = Get-UserDropFolders
    Write-Host

    # 1. restart + running tools
    Write-Section 'PC and running programs'
    try {
        $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
        $up = $now - $boot
        Write-Host ('  PC started {0} ({1}h {2}m ago)' -f $boot.ToString('yyyy-MM-dd HH:mm'), [int][math]::Floor($up.TotalHours), $up.Minutes) -ForegroundColor Gray
        if ($up.TotalMinutes -lt 20) { Write-Alert 'Yellow' "PC was restarted $([int]$up.TotalMinutes) minutes ago - a restart clears some traces" $alerts }
    } catch {}
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $hw = "$($cs.Manufacturer) $($cs.Model)"
        if ($hw -match 'VMware|VirtualBox|QEMU|KVM|Xen|Parallels|Virtual Machine|Hyper-V|innotek') { Write-Alert 'Yellow' "Running inside a virtual machine ($hw)" $alerts }
    } catch {}
    foreach ($pr in (Get-Process -ErrorAction SilentlyContinue)) {
        $lvl = Get-ToolLevel "$($pr.ProcessName).exe"
        if (-not $lvl -and (Get-ToolLevel $pr.MainWindowTitle) -eq 'Red') { $lvl = 'Red' }
        if ($lvl) { Write-Alert $lvl "Running now: $($pr.ProcessName) (PID $($pr.Id))$(if ($pr.MainWindowTitle) { " - '$($pr.MainWindowTitle)'" })" $alerts }
    }
    Write-Host

    # 2. services that record what ran
    Write-Section 'Logging services'
    $svcRules = @(
        @{ Name = 'EventLog'; Level = 'Red';    Why = 'records Windows event logs' },
        @{ Name = 'SysMain';  Level = 'Yellow'; Why = 'keeps the Prefetch record of programs that ran (some people turn it off for speed)' },
        @{ Name = 'PcaSvc';   Level = 'Yellow'; Why = 'Program Compatibility Assistant, records programs that ran' },
        @{ Name = 'DiagTrack';Level = 'Yellow'; Why = 'diagnostics service (often turned off by privacy tweaks)' }
    )
    $okSvc = 0
    foreach ($r in $svcRules) {
        $svc = Get-Service -Name $r.Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') { Write-Alert $r.Level "$($r.Name) is $($svc.Status) - it $($r.Why)" $alerts } else { $okSvc++ }
    }
    try {
        $bamDrv = Get-CimInstance Win32_SystemDriver -Filter "Name='bam'" -ErrorAction Stop
        if ($bamDrv -and $bamDrv.State -ne 'Running') { Write-Alert 'Red' "BAM is $($bamDrv.State) - it records which programs ran" $alerts }
    } catch {}
    if ($okSvc -eq $svcRules.Count) { Write-Host '  All running.' -ForegroundColor Green }
    Write-Host

    # 3. BAM: programs that ran (needs admin)
    Write-Section 'Programs that ran in the last 24 hours (BAM)'
    if (-not $admin) {
        Write-Host '  Skipped - needs administrator.' -ForegroundColor DarkGray
    } elseif (-not (Initialize-Native)) {
        Write-Host '  Skipped - could not load the helper.' -ForegroundColor DarkGray
    } else {
        $devMap = @{}
        foreach ($d in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            $dev = [ModAnzerNative]::DosDevice("$($d.Name):")
            if ($dev) { $devMap[$dev] = "$($d.Name):" }
        }
        $entries = @()
        foreach ($root in @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')) {
            if (-not (Test-Path $root)) { continue }
            foreach ($k in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
                foreach ($n in $k.GetValueNames()) {
                    $v = $k.GetValue($n)
                    if ($v -isnot [byte[]] -or $v.Length -lt 8) { continue }
                    try { $t = [DateTime]::FromFileTime([BitConverter]::ToInt64($v, 0)) } catch { continue }
                    if ($t -lt $day) { continue }
                    $path = $n
                    foreach ($dev in $devMap.Keys) { if ($path.StartsWith("$dev\", [StringComparison]::OrdinalIgnoreCase)) { $path = $devMap[$dev] + $path.Substring($dev.Length); break } }
                    $entries += [PSCustomObject]@{ Path = $path; Time = $t }
                }
            }
        }
        $flagged = 0
        foreach ($e in ($entries | Sort-Object Time -Descending)) {
            $file = [IO.Path]::GetFileName($e.Path)
            $when = $e.Time.ToString('HH:mm')
            $exists = $false
            if ($e.Path -match '^[A-Za-z]:\\') { $exists = Test-Path -LiteralPath $e.Path }
            $lvl = Get-ToolLevel $file
            $inDrop = Test-UnderPath $e.Path $drop
            if ($lvl) { $flagged++; Write-Alert $lvl "Ran at ${when}: $(Get-ShortPath $e.Path)$(if (-not $exists) { ' (file is gone now)' })" $alerts }
            elseif (-not $exists -and $e.Path -match '\\Users\\') { $flagged++; Write-Alert 'Red' "Ran at $when and was DELETED afterwards: $(Get-ShortPath $e.Path)" $alerts }
            elseif ($inDrop -and $exists -and -not (Get-Signer $e.Path)) { $flagged++; Write-Alert 'Yellow' "Unsigned program from a user folder ran at ${when}: $(Get-ShortPath $e.Path)" $alerts }
        }
        Write-Host "  $($entries.Count) programs ran, $flagged flagged." -ForegroundColor $(if ($flagged) { 'Gray' } else { 'Green' })
    }
    Write-Host

    # 4. Prefetch (needs admin)
    Write-Section 'Prefetch'
    $pfDir = Join-Path $env:SystemRoot 'Prefetch'
    if (-not $admin) {
        Write-Host '  Skipped - needs administrator.' -ForegroundColor DarkGray
    } else {
        $pf = @(Get-ChildItem -LiteralPath $pfDir -Filter *.pf -File -ErrorAction SilentlyContinue)
        $sysMain = Get-Service SysMain -ErrorAction SilentlyContinue
        if ($pf.Count -eq 0) {
            if ($sysMain -and $sysMain.Status -eq 'Running') { Write-Alert 'Red' 'Prefetch folder is empty although Prefetch is on - it was probably cleared' $alerts }
            else { Write-Host '  Empty (Prefetch is turned off).' -ForegroundColor DarkGray }
        } else {
            $oldest = ($pf | Sort-Object CreationTime | Select-Object -First 1).CreationTime
            if ($pf.Count -lt 40 -and $oldest -gt $day) { Write-Alert 'Yellow' "Only $($pf.Count) Prefetch files, all created in the last 24 hours - it may have been cleared" $alerts }
            $recentPf = @($pf | Where-Object { $_.LastWriteTime -ge $day })
            $hit = 0
            foreach ($f in $recentPf) {
                $exe = $f.BaseName -replace '-[0-9A-F]{8}$', ''
                $lvl = Get-ToolLevel $exe
                if ($lvl) { $hit++; Write-Alert $lvl "Prefetch: $exe ran at $($f.LastWriteTime.ToString('HH:mm'))" $alerts }
            }
            Write-Host "  $($recentPf.Count) programs ran in the last 24 hours, $hit flagged." -ForegroundColor $(if ($hit) { 'Gray' } else { 'Green' })
        }
    }
    Write-Host

    # 5. PowerShell history
    Write-Section 'PowerShell history'
    $histPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (-not (Test-Path -LiteralPath $histPath)) {
        Write-Host '  No PowerShell history file.' -ForegroundColor DarkGray
    } else {
        $rules = @(
            @{ Re = 'Clear-History|ConsoleHost_history|HistorySaveStyle'; Level = 'Red'; Why = 'cleared or turned off PowerShell history' },
            @{ Re = 'wevtutil(\.exe)?\s+(cl|clear-log)|Clear-EventLog|Remove-EventLog|Limit-EventLog'; Level = 'Red'; Why = 'cleared event logs' },
            @{ Re = 'fsutil(\.exe)?\s+usn\s+deletejournal'; Level = 'Red'; Why = 'deleted the file change journal' },
            @{ Re = '(Remove-Item|\bdel\b|\berase\b|\brm\b|\brmdir\b|\brd\b|\bri\b).*(\.jar|[\\/]mods\b|\.minecraft|prefetch|\.pf\b|\.dll\b)'; Level = 'Red'; Why = 'deleted mods or evidence' },
            @{ Re = '(Set|Add)-MpPreference.*Exclusion'; Level = 'Red'; Why = 'added an antivirus exclusion' },
            @{ Re = '(Stop|Set)-Service.*(SysMain|EventLog|PcaSvc|DiagTrack|bam)|sc(\.exe)?\s+(stop|config)\s+(SysMain|EventLog|PcaSvc|DiagTrack|bam)'; Level = 'Red'; Why = 'stopped a logging service' },
            @{ Re = 'reg(\.exe)?\s+delete.*(bam|UserAssist|ShellBag|Prefetch)|Remove-Item.*HKLM:.*bam'; Level = 'Red'; Why = 'deleted execution history from the registry' },
            @{ Re = '(Invoke-WebRequest|\biwr\b|\bcurl\b|\bwget\b|Start-BitsTransfer|DownloadFile|Invoke-RestMethod|\birm\b).*\.(jar|dll|exe)\b'; Level = 'Yellow'; Why = 'downloaded a program or mod from the command line' }
        )
        $lines = @(Get-Content -LiteralPath $histPath -ErrorAction SilentlyContinue)
        $hit = 0
        foreach ($line in $lines) {
            if ($line -match 'ModAnzer') { continue }
            foreach ($r in $rules) {
                if ($line -match $r.Re) {
                    $hit++
                    $shown = $line.Trim(); if ($shown.Length -gt 110) { $shown = $shown.Substring(0, 110) + '...' }
                    Write-Alert $r.Level "$($r.Why): $shown" $alerts
                    break
                }
            }
        }
        $age = $now - (Get-Item -LiteralPath $histPath).LastWriteTime
        Write-Host "  $($lines.Count) commands, $hit flagged (last change $([int]$age.TotalHours)h ago)." -ForegroundColor $(if ($hit) { 'Gray' } else { 'Green' })
    }
    Write-Host

    # 6. event logs
    Write-Section 'Event logs'
    $ev = 0
    $queries = @(
        @{ Log = 'System'; Id = 104; Level = 'Red'; Why = 'an event log was cleared'; Admin = $false },
        @{ Log = 'Security'; Id = 1102; Level = 'Red'; Why = 'the Security log was cleared'; Admin = $true },
        @{ Log = 'Application'; Id = 3079; Level = 'Red'; Why = 'the file change journal was deleted'; Admin = $false }
    )
    foreach ($q in $queries) {
        if ($q.Admin -and -not $admin) { continue }
        try {
            foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = $q.Log; Id = $q.Id; StartTime = $week } -MaxEvents 5 -ErrorAction Stop)) {
                $ev++
                Write-Alert $q.Level "$($e.TimeCreated.ToString('yyyy-MM-dd HH:mm')): $($q.Why) ($($q.Log) event $($q.Id))" $alerts
            }
        } catch {}
    }
    if ($ev -eq 0) { Write-Host "  No log clearing in the last 7 days$(if (-not $admin) { ' (Security log skipped - needs administrator)' })." -ForegroundColor Green }
    Write-Host

    # 7. USB drives
    Write-Section 'USB drives'
    $usb = 0
    foreach ($d in @(Get-PnpDevice -InstanceId 'USBSTOR\*' -ErrorAction SilentlyContinue)) {
        $last = $null
        try { $last = (Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_LastArrivalDate' -ErrorAction Stop).Data } catch {}
        if ($d.Status -eq 'OK') { $usb++; Write-Alert 'Yellow' "USB drive plugged in now: $($d.FriendlyName)" $alerts }
        elseif ($last -and $last -ge $day) { $usb++; Write-Alert 'Yellow' "USB drive was plugged in at $($last.ToString('HH:mm')): $($d.FriendlyName)" $alerts }
    }
    if ($usb -eq 0) { Write-Host '  No USB drives in the last 24 hours.' -ForegroundColor Green }
    Write-Host

    # 8. Recycle Bin + recent downloads
    Write-Section 'Deleted and downloaded files'
    $files = 0
    try {
        $rb = (New-Object -ComObject Shell.Application).NameSpace(10)
        foreach ($it in @($rb.Items())) {
            $ext = [IO.Path]::GetExtension([string]$it.Path).ToLowerInvariant()
            if ($ext -notin @('.jar', '.dll', '.exe', '.ahk', '.pf')) { continue }
            $when = $null
            try { $when = [DateTime]$it.ExtendedProperty('System.Recycle.DateDeleted') } catch {}
            if ($when -and $when -lt $week) { continue }
            $from = ''
            try { $from = [string]$it.ExtendedProperty('System.Recycle.DeletedFrom') } catch {}
            $files++
            $lvl = if ($ext -in @('.jar', '.dll', '.pf') -or (Get-ToolLevel $it.Name) -eq 'Red') { 'Red' } else { 'Yellow' }
            Write-Alert $lvl "In the Recycle Bin: $($it.Name)$(if ($from) { " (from $(Get-ShortPath $from))" })$(if ($when) { ", deleted $($when.ToString('yyyy-MM-dd HH:mm'))" })" $alerts
        }
    } catch {}
    foreach ($dir in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -Recurse -Depth 1 -Include *.jar, *.dll, *.exe, *.ahk -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $week })) {
            $lvl = Get-ToolLevel $f.Name
            if (-not $lvl -and $f.Extension -in @('.jar', '.ahk')) { $lvl = 'Yellow' }
            if ($lvl) { $files++; Write-Alert $lvl "Recent file: $(Get-ShortPath $f.FullName) ($($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" $alerts }
        }
    }
    if ($files -eq 0) { Write-Host '  Nothing suspicious in the Recycle Bin, Downloads or Desktop.' -ForegroundColor Green }
    Write-Host

    # 9. Minecraft accounts (names only)
    Write-Section 'Minecraft accounts used on this PC (names only)'
    $names = Get-MinecraftAccountNames
    if ($names.Count -eq 0) { Write-Host '  None found.' -ForegroundColor DarkGray }
    else {
        Write-Host "  $(@($names | Sort-Object) -join ', ')" -ForegroundColor Gray
        if ($names.Count -gt 1) { Write-Alert 'Yellow' "$($names.Count) different Minecraft accounts used on this PC: $(@($names | Sort-Object) -join ', ')" $alerts }
    }
    Write-Host

    $script:RunReport.System = [ordered]@{ Admin = $admin; Alerts = @($alerts | ForEach-Object { [ordered]@{ Time = $_.Time; Level = $_.Level; Text = $_.Text } }) }
    $script:RunReport.Accounts = @($names | Sort-Object)
    Write-CheckSummary 'System Check summary' $alerts
    Write-Host
    Write-Host 'These are traces, not proof: check each one with the player before deciding.' -ForegroundColor DarkGray
    Write-Host
}

# ---------------------------------------------------------------- start menu

if ($Mode -and $Mode -notin @('mods', 'injection', 'system', 'full')) {
    Write-Host "Unknown -Mode '$Mode'. Use mods, injection, system or full." -ForegroundColor Red
    $Mode = ''
}

if (-not $Mode) {
    if ($Path) { $Mode = 'mods' }
    else {
        Write-Host 'What do you want to do?' -ForegroundColor White
        Write-Host '  1) ' -ForegroundColor Yellow -NoNewline; Write-Host 'Mod Analyzer       ' -NoNewline; Write-Host '- check the mods in your mods folders  [default]' -ForegroundColor DarkGray
        Write-Host '  2) ' -ForegroundColor Yellow -NoNewline; Write-Host 'Injection Checker  ' -NoNewline; Write-Host '- check the running game, its memory, and watch it live' -ForegroundColor DarkGray
        Write-Host '  3) ' -ForegroundColor Yellow -NoNewline; Write-Host 'System Check       ' -NoNewline; Write-Host '- traces: programs that ran, deleted files, cleared logs, USB' -ForegroundColor DarkGray
        Write-Host '  4) ' -ForegroundColor Yellow -NoNewline; Write-Host 'Full Screenshare   ' -NoNewline; Write-Host '- all three, one after another' -ForegroundColor DarkGray
        Write-Host
        while (-not $Mode) {
            $in = (Read-Host 'Choose 1-4').Trim()
            switch ($in) {
                ''  { $Mode = 'mods' }
                '1' { $Mode = 'mods' }
                '2' { $Mode = 'injection' }
                '3' { $Mode = 'system' }
                '4' { $Mode = 'full' }
                default { Write-Host 'Type a number from 1 to 4.' -ForegroundColor Red }
            }
        }
        Write-Host
    }
}

# The System Check and the memory scan see more as administrator. Offer to restart elevated.
if ($Mode -ne 'mods' -and $IsWindowsOS -and -not $NoPause -and -not (Test-Admin)) {
    Write-Host 'Administrator rights let ModAnzer read execution history, Prefetch, the Security log and the game''s memory.' -ForegroundColor White
    $ans = (Read-Host 'Restart as administrator for a full check? [Y/n]').Trim()
    if ($ans -eq '' -or $ans -match '^[yY]') {
        $extra = "-Mode $Mode -SkipIntro"
        if ($Offline) { $extra += ' -Offline' }
        if ($LiveSeconds -gt 0) { $extra += " -LiveSeconds $LiveSeconds" }
        if ($NoSend) { $extra += ' -NoSend' }
        if ($PSCommandPath) {
            $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $extra"
        } else {
            $argLine = "-NoProfile -ExecutionPolicy Bypass -Command `"& ([scriptblock]::Create(((Invoke-RestMethod 'https://ryfttiers-modanzer.onrender.com/ModAnzer.txt') -join [char]10))) $extra`""
        }
        try {
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argLine -ErrorAction Stop
            Write-Host 'Continuing in the administrator window. You can close this one.' -ForegroundColor Green
            Start-Sleep -Seconds 2
            return
        } catch {
            Write-Host 'Administrator was declined - continuing with what a normal user can see.' -ForegroundColor Yellow
        }
    }
    Write-Host
}

function Invoke-ModAnalyzer {
    $running = @(Get-RunningGameDirs)
    if ($running.Count -gt 0) {
        Write-Section 'Running Minecraft'
        foreach ($r in $running) {
            $up = ''
            if ($r.Started) {
                $t = (Get-Date) - $r.Started
                $up = ' - up {0}h {1}m {2}s' -f [int][math]::Floor($t.TotalHours), $t.Minutes, $t.Seconds
            }
            Write-Host "> PID $($r.Pid)$up" -ForegroundColor White
            Write-Host "  $(Get-ShortPath $r.Dir)" -ForegroundColor Gray
        }
        Write-Host
    }

    $folders = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    function Fix-Sep([string]$p) { return $p.Replace('\', [IO.Path]::DirectorySeparatorChar) }

    $home_ = $env:USERPROFILE
    $Launchers = @(
        @{ Name = 'Minecraft Launcher (.minecraft, Badlion, SKLauncher)'; Roots = @("$env:APPDATA\.minecraft") },
        @{ Name = 'CurseForge';            Roots = @("$home_\curseforge\minecraft\Instances", "$home_\Documents\curseforge\minecraft\Instances", "$home_\Twitch\Minecraft\Instances") },
        @{ Name = 'Modrinth App';          Roots = @("$env:APPDATA\ModrinthApp", "$env:APPDATA\com.modrinth.theseus") },
        @{ Name = 'Prism / MultiMC / PolyMC'; Roots = @("$env:APPDATA\PrismLauncher", "$env:APPDATA\PolyMC", "$env:LOCALAPPDATA\Programs\PrismLauncher", "$env:LOCALAPPDATA\Programs\MultiMC") },
        @{ Name = 'ATLauncher';            Roots = @("$env:APPDATA\ATLauncher") },
        @{ Name = 'GDLauncher';            Roots = @("$env:APPDATA\gdlauncher_next", "$env:APPDATA\gdlauncher_carbon") },
        @{ Name = 'Lunar Client';          Roots = @("$home_\.lunarclient") },
        @{ Name = 'Dawn Client (formerly Feather)'; Roots = @("$env:APPDATA\.dawn", "$home_\.dawn", "$env:APPDATA\.feather") },
        @{ Name = 'Fast Client';           Roots = @("$env:APPDATA\.fastclient", "$home_\.fastclient", "$env:APPDATA\FastClient", "$env:LOCALAPPDATA\FastClient", "$env:LOCALAPPDATA\Programs\FastClient") },
        @{ Name = 'TLauncher';             Roots = @("$env:APPDATA\.tlauncher", "$env:APPDATA\.minecraft") },
        @{ Name = 'Technic';               Roots = @("$env:APPDATA\.technic") }
    )

    # Add the mods folders found under each root
    function Add-FromRoots($rootList) {
        foreach ($root in $rootList) {
            if (-not $root) { continue }
            $root = Fix-Sep $root
            if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
            $leaf = [IO.Path]::GetFileName($root.TrimEnd('\', '/'))
            if ($ModFolderNames -contains $leaf.ToLowerInvariant()) { [void]$folders.Add($root); continue }
            foreach ($f in (Find-ModFolders $root)) { [void]$folders.Add($f) }
        }
    }

    # A folder the user typed: use it if it holds jars, otherwise look for mods folders inside it
    function Add-UserFolder([string]$p) {
        $p = $p.Trim().Trim('"').Trim("'")
        if ($p -and -not (Test-Path -LiteralPath $p -PathType Container) -and (Test-Path -LiteralPath (Fix-Sep $p) -PathType Container)) { $p = Fix-Sep $p }
        if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Container)) { return $false }
        $p = (Resolve-Path -LiteralPath $p).ProviderPath
        $before = $folders.Count
        if (Get-ChildItem -LiteralPath $p -Filter *.jar -File -Recurse -Depth 1 -ErrorAction SilentlyContinue | Select-Object -First 1) {
            [void]$folders.Add($p)
        }
        foreach ($f in (Find-ModFolders $p)) { [void]$folders.Add($f) }
        if ($folders.Count -eq $before) { [void]$folders.Add($p) }
        return $true
    }

    if ($Path) {
        foreach ($p in $Path) {
            if (-not (Add-UserFolder $p)) { Write-Host "Not a folder: $p" -ForegroundColor Red }
        }
    } else {
        $otherNum = $Launchers.Count + 2
        Write-Host 'Which launcher do you use?' -ForegroundColor White
        Write-Host '  1) ' -ForegroundColor Yellow -NoNewline; Write-Host 'Scan everything (auto-detect)  ' -NoNewline; Write-Host '[default]' -ForegroundColor DarkGray
        for ($n = 0; $n -lt $Launchers.Count; $n++) {
            Write-Host ('{0,3}) ' -f ($n + 2)) -ForegroundColor Yellow -NoNewline; Write-Host $Launchers[$n].Name
        }
        Write-Host ('{0,3}) ' -f $otherNum) -ForegroundColor Yellow -NoNewline; Write-Host 'Other (type the path to your mods folder)'
        Write-Host

        $choice = $null
        if ($Launcher -or $NoPause) {
            $choice = 1
            if ($Launcher -and $Launcher -ne 'all') {
                for ($n = 0; $n -lt $Launchers.Count; $n++) {
                    if ($Launchers[$n].Name -like "*$Launcher*") { $choice = $n + 2; break }
                }
            }
            Write-Host "Choose 1-$($otherNum): $choice" -ForegroundColor DarkGray
        }
        while ($null -eq $choice) {
            $in = (Read-Host "Choose 1-$otherNum").Trim()
            if ($in -eq '') { $in = '1' }
            $num = 0
            if ([int]::TryParse($in, [ref]$num) -and $num -ge 1 -and $num -le $otherNum) { $choice = $num }
            else { Write-Host "Type a number from 1 to $otherNum." -ForegroundColor Red }
        }
        Write-Host

        if ($choice -eq $otherNum) {
            while ($true) {
                $typed = Read-Host 'Path to the mods folder'
                if (Add-UserFolder $typed) { break }
                Write-Host 'That folder does not exist. Try again (you can paste it from File Explorer).' -ForegroundColor Red
            }
        } elseif ($choice -ge 2) {
            $pick = $Launchers[$choice - 2]
            Write-Host "[*] Looking for $($pick.Name) mods folders..." -ForegroundColor Yellow -NoNewline
            Add-FromRoots $pick.Roots
            if ($folders.Count -eq 0) {
                Write-Host "`r$(' ' * 70)`r" -NoNewline
                Write-Host "No $($pick.Name) mods folder found in the usual place." -ForegroundColor Red
                while ($true) {
                    if ($NoPause) { Write-Host 'Scanning everything instead.' -ForegroundColor DarkGray; $choice = 1; break }
                    $typed = Read-Host 'Paste the path to your mods folder (or press Enter to scan everything)'
                    if (-not $typed.Trim()) { $choice = 1; break }
                    if (Add-UserFolder $typed) { break }
                    Write-Host 'That folder does not exist. Try again.' -ForegroundColor Red
                }
            }
        }

        if ($choice -eq 1) {
            Write-Host '[*] Looking for mods folders...' -ForegroundColor Yellow -NoNewline
            $all = @()
            foreach ($l in $Launchers) { $all += $l.Roots }

            # Microsoft Store launcher
            Get-ChildItem -Path (Fix-Sep "$env:LOCALAPPDATA\Packages") -Directory -Filter 'Microsoft.4297127D64EC6_*' -ErrorAction SilentlyContinue |
                ForEach-Object { $all += (Join-Path $_.FullName 'LocalCache\Roaming\.minecraft') }

            # Any dot-folder in AppData\Roaming or the user folder (.dawn, .badlion, other clients)
            foreach ($base in @($env:APPDATA, $home_)) {
                if (-not $base) { continue }
                Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name.StartsWith('.') -and ($SkipDirs -notcontains $_.Name.ToLowerInvariant()) } |
                    ForEach-Object { $all += $_.FullName }
            }

            # Running game directories
            foreach ($r in $running) { $all += $r.Dir }

            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            Add-FromRoots (@($all | Where-Object { $_ -and $seen.Add((Fix-Sep $_)) }))
        }
    }

    # Collect jars (also one level of subfolders, e.g. mods\1.21\)
    $jars = @()
    foreach ($f in $folders) {
        $files = @(Get-ChildItem -LiteralPath $f -Filter *.jar -File -Recurse -Depth 1 -ErrorAction SilentlyContinue)
        foreach ($j in $files) {
            $jars += [PSCustomObject]@{ Folder = $f; File = $j }
        }
    }

    Write-Host "`r$(' ' * 60)`r" -NoNewline
    $withJars = @($jars | Select-Object -ExpandProperty Folder -Unique)

    if ($withJars.Count -eq 0) {
        Write-Host 'No mods found.' -ForegroundColor Red
        Write-Host 'Run it again and choose "Other" to type the path to your mods folder.' -ForegroundColor DarkGray
        return
    }

    Write-Section "Mod folders found ($($withJars.Count))"
    foreach ($f in $withJars) {
        $count = @($jars | Where-Object { $_.Folder -eq $f }).Count
        Write-Host ("> {0,-11}" -f (Get-LauncherName $f)) -ForegroundColor White -NoNewline
        Write-Host ("{0,4} jars  " -f $count) -ForegroundColor DarkGray -NoNewline
        Write-Host (Get-ShortPath $f) -ForegroundColor Gray
    }
    Write-Host

    # ---------------------------------------------------------------- 2. hash

    $i = 0
    foreach ($j in $jars) {
        $i++
        Write-Host "`r[*] Hashing $i / $($jars.Count)" -ForegroundColor Yellow -NoNewline
        try { $h = (Get-FileHash -LiteralPath $j.File.FullName -Algorithm SHA1).Hash.ToLowerInvariant() } catch { $h = $null }
        $j | Add-Member -NotePropertyName Hash -NotePropertyValue $h
    }
    $hashes = @($jars | Where-Object { $_.Hash } | Select-Object -ExpandProperty Hash -Unique)

    # ---------------------------------------------------------------- 3. look up

    $known = @{}   # hash -> mod name
    $slugByHash = @{}   # hash -> Modrinth slug

    if (-not $Offline -and $hashes.Count -gt 0) {
        Write-Host "`r[*] Checking $($hashes.Count) unique mods on Modrinth...      " -ForegroundColor Yellow -NoNewline
        $projectIdByHash = @{}
        try {
            for ($n = 0; $n -lt $hashes.Count; $n += 500) {
                $chunk = @($hashes[$n..([math]::Min($n + 499, $hashes.Count - 1))])
                $body  = @{ hashes = $chunk; algorithm = 'sha1' } | ConvertTo-Json -Compress
                $resp  = Invoke-Json 'https://api.modrinth.com/v2/version_files' 'Post' $body
                foreach ($prop in $resp.PSObject.Properties) {
                    if ($prop.Value.project_id) { $projectIdByHash[$prop.Name.ToLowerInvariant()] = $prop.Value.project_id }
                }
            }
            $ids = @($projectIdByHash.Values | Select-Object -Unique)
            $titleById = @{}
            $slugById = @{}
            for ($n = 0; $n -lt $ids.Count; $n += 100) {
                $chunk = @($ids[$n..([math]::Min($n + 99, $ids.Count - 1))])
                $q = [uri]::EscapeDataString((ConvertTo-Json -InputObject $chunk -Compress))
                foreach ($proj in (Invoke-Json "https://api.modrinth.com/v2/projects?ids=$q")) { $titleById[$proj.id] = $proj.title; $slugById[$proj.id] = $proj.slug }
            }
            foreach ($h in $projectIdByHash.Keys) {
                $t = $titleById[$projectIdByHash[$h]]
                if (-not $t) { $t = '(Modrinth project)' }
                $known[$h] = "$t"
                if ($slugById[$projectIdByHash[$h]]) { $slugByHash[$h] = [string]$slugById[$projectIdByHash[$h]] }
            }
        } catch {
            Write-Host "`r[!] Modrinth lookup failed: $($_.Exception.Message)" -ForegroundColor Red
        }

        $left = @($hashes | Where-Object { -not $known.ContainsKey($_) })
        $i = 0
        foreach ($h in $left) {
            $i++
            Write-Host "`r[*] Checking Megabase $i / $($left.Count)              " -ForegroundColor Yellow -NoNewline
            try {
                $r = Invoke-Json "https://megabase.vercel.app/api/query?hash=$h"
                if (-not $r.error -and $r.data -and $r.data.name) { $known[$h] = "$($r.data.name)" }
            } catch {}
        }
    }

    if (-not $Offline) {
        try {
            $list = Invoke-RestMethod -Uri $TrustedListUrl -UseBasicParsing -UserAgent $UserAgent -TimeoutSec 15
            foreach ($line in ([string]$list -split "`n")) {
                if ($line -match '^\s*([0-9a-fA-F]{40})\s+(.+?)\s*$') { $TrustedMods[$Matches[1].ToLowerInvariant()] = $Matches[2] }
            }
        } catch {}
    }
    foreach ($h in $hashes) {
        if ($TrustedMods.ContainsKey($h)) { $known[$h] = "$($TrustedMods[$h]) (trusted)" }
    }

    # CurseForge by fingerprint
    if (-not $CurseForgeApiKey -and $env:MODANZER_CF_KEY) { $CurseForgeApiKey = $env:MODANZER_CF_KEY }
    if (-not $Offline -and ($CurseForgeApiKey -or $CurseForgeProxyUrl)) {
        $left = @($hashes | Where-Object { -not $known.ContainsKey($_) })
        if ($left.Count -gt 0) {
            $hashByFp = @{}
            $i = 0
            foreach ($h in $left) {
                $i++
                Write-Host "`r[*] CurseForge fingerprint $i / $($left.Count)              " -ForegroundColor Yellow -NoNewline
                $file = ($jars | Where-Object { $_.Hash -eq $h } | Select-Object -First 1).File
                try { $hashByFp[[string](Get-CurseForgeFingerprint $file.FullName)] = $h } catch {}
            }
            Write-Host "`r[*] Checking $($hashByFp.Count) mods on CurseForge...            " -ForegroundColor Yellow -NoNewline
            $fpList = @($hashByFp.Keys | ForEach-Object { [uint32]$_ })
            try {
                $nameByFp = @{}
                if ($CurseForgeApiKey) {
                    $cfHeaders = @{ 'x-api-key' = $CurseForgeApiKey; 'Accept' = 'application/json' }
                    $body = @{ fingerprints = $fpList } | ConvertTo-Json -Compress
                    $r = Invoke-RestMethod -Uri 'https://api.curseforge.com/v1/fingerprints/432' -Method Post -Body $body -ContentType 'application/json' -Headers $cfHeaders -UseBasicParsing -UserAgent $UserAgent -TimeoutSec 20
                    $modIdByFp = @{}
                    foreach ($m in @($r.data.exactMatches)) { $modIdByFp[[string]$m.file.fileFingerprint] = $m.file.modId }
                    if ($modIdByFp.Count -gt 0) {
                        $body = @{ modIds = @($modIdByFp.Values | Select-Object -Unique) } | ConvertTo-Json -Compress
                        $mods = Invoke-RestMethod -Uri 'https://api.curseforge.com/v1/mods' -Method Post -Body $body -ContentType 'application/json' -Headers $cfHeaders -UseBasicParsing -UserAgent $UserAgent -TimeoutSec 20
                        $nameById = @{}
                        foreach ($mod in @($mods.data)) { $nameById[[string]$mod.id] = $mod.name }
                        foreach ($fp in $modIdByFp.Keys) { $nameByFp[$fp] = $nameById[[string]$modIdByFp[$fp]] }
                    }
                } else {
                    for ($n = 0; $n -lt $fpList.Count; $n += 1000) {
                        $chunk = @($fpList[$n..([math]::Min($n + 999, $fpList.Count - 1))])
                        $body = @{ fingerprints = $chunk } | ConvertTo-Json -Compress
                        $r = Invoke-RestMethod -Uri $CurseForgeProxyUrl -Method Post -Body $body -ContentType 'application/json' -UseBasicParsing -UserAgent $UserAgent -TimeoutSec 30
                        foreach ($prop in $r.matches.PSObject.Properties) { $nameByFp[$prop.Name] = $prop.Value.name }
                    }
                }
                foreach ($fp in $nameByFp.Keys) {
                    if ($hashByFp.ContainsKey($fp)) {
                        $n = $nameByFp[$fp]
                        if (-not $n) { $n = '(CurseForge project)' }
                        $known[$hashByFp[$fp]] = "$n [CurseForge]"
                    }
                }
            } catch {
                $msg = $_.Exception.Message
                try { if ($_.ErrorDetails.Message) { $msg = ($_.ErrorDetails.Message | ConvertFrom-Json).error } } catch {}
                Write-Host "`r[!] CurseForge lookup failed: $msg" -ForegroundColor Red
            }
        }
    }

    # ---------------------------------------------------------------- 3b. cheats among known mods

    $flagged = @{}   # hash -> why a known mod counts as a cheat
    $flaggedSlugs = @{}; $flaggedHashes = @{}
    if (-not $Offline) {
        try {
            $list = Invoke-RestMethod -Uri $FlaggedListUrl -UseBasicParsing -UserAgent $UserAgent -TimeoutSec 15
            foreach ($line in ([string]$list -split "`n")) {
                $line = ($line -replace '#.*$', '').Trim()
                if ($line -match '^([0-9a-fA-F]{40})(?:\s+(.+))?$') { $flaggedHashes[$Matches[1].ToLowerInvariant()] = "$($Matches[2])" }
                elseif ($line -match '^([A-Za-z0-9_.-]+)(?:\s+(.+))?$') { $flaggedSlugs[$Matches[1].ToLowerInvariant()] = "$($Matches[2])" }
            }
        } catch {}
    }
    $knownHashes = @($hashes | Where-Object { $known.ContainsKey($_) -and -not $TrustedMods.ContainsKey($_) })
    $jarByHash = @{}
    foreach ($j in $jars) { if ($j.Hash -and -not $jarByHash.ContainsKey($j.Hash)) { $jarByHash[$j.Hash] = $j.File } }
    $i = 0
    foreach ($h in $knownHashes) {
        $i++
        Write-Host "`r[*] Checking known mods for cheats $i / $($knownHashes.Count)      " -ForegroundColor Yellow -NoNewline
        $slug = [string]$slugByHash[$h]
        if ($flaggedHashes.ContainsKey($h)) { $flagged[$h] = "on the flagged list $($flaggedHashes[$h])".Trim(); continue }
        if ($slug -and $flaggedSlugs.ContainsKey($slug.ToLowerInvariant())) { $flagged[$h] = "flagged Modrinth project '$slug' $($flaggedSlugs[$slug.ToLowerInvariant()])".Trim(); continue }
        $nm = $FlaggedNameRegex.Match("$($known[$h]) $slug")
        if ($nm.Success) { $flagged[$h] = "name says '$($nm.Value.Trim())'"; continue }
        # Class names only (no unpacking), so this stays quick even with hundreds of mods.
        $jar = $jarByHash[$h]
        $zip = $null
        try {
            $zip = [IO.Compression.ZipFile]::OpenRead($jar.FullName)
            $found = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($entry in $zip.Entries) {
                if (-not $entry.FullName.EndsWith('.class')) { continue }
                $leaf = [IO.Path]::GetFileNameWithoutExtension($entry.Name) -replace '\$.*$', ''
                if ($CheatClassRegex.IsMatch($leaf)) { [void]$found.Add($leaf) }
            }
            if ($found.Count -gt 0) { $flagged[$h] = "has cheat modules: $(@($found | Sort-Object) -join ', ')" }
        } catch {} finally { if ($zip) { $zip.Dispose() } }
    }

    # ---------------------------------------------------------------- 4. scan unknown jars

    $scanned = @{}   # hash -> list of hits
    $unknownHashes = @($hashes | Where-Object { -not $known.ContainsKey($_) })
    $i = 0
    foreach ($h in $unknownHashes) {
        $i++
        Write-Host "`r[*] Scanning unknown mods for cheat strings $i / $($unknownHashes.Count)      " -ForegroundColor Yellow -NoNewline
        $jar  = ($jars | Where-Object { $_.Hash -eq $h } | Select-Object -First 1).File
        $hits = New-Object 'System.Collections.Generic.List[object]'
        try {
            $fs = [IO.File]::OpenRead($jar.FullName)
            try { Search-Jar $fs $jar.Name $hits } finally { $fs.Dispose() }
        } catch {
            $hits.Add([PSCustomObject]@{ Where = $jar.Name; Strings = @("could not open: $($_.Exception.Message)"); Strong = $false })
        }
        $scanned[$h] = $hits
    }

    Write-Host "`r$(' ' * 80)`r" -NoNewline

    # ---------------------------------------------------------------- 5. report

    $totalCheat = 0; $totalUnknown = 0; $totalVerified = 0; $totalCf = 0; $totalCheck = 0
    $cheatList = New-Object 'System.Collections.Generic.List[object]'
    $unknownList = New-Object 'System.Collections.Generic.List[object]'
    $checkList = New-Object 'System.Collections.Generic.List[object]'
    $allList = New-Object 'System.Collections.Generic.List[object]'

    # "Launcher > instance" for a mods folder, e.g. "Modrinth > Atzlk_s PMW"
    function Get-InstanceLabel([string]$modsFolder) {
        $launcher = Get-LauncherName $modsFolder
        $parent = Split-Path -Parent $modsFolder
        $inst = Split-Path -Leaf $parent
        if ($inst -in @('.minecraft', 'minecraft', '')) {
            $up = Split-Path -Leaf (Split-Path -Parent $parent)
            if ($up -and $up -notin @('Roaming', 'AppData') -and -not $up.StartsWith('.')) { $inst = $up } else { $inst = $null }
        }
        if ($inst -and $inst.StartsWith('.')) { $inst = $null }
        if ($inst -and $inst -ne $launcher -and ".$inst" -ne $launcher -and $inst -ne ".$launcher".TrimStart('.')) { return "$launcher > $inst" }
        return $launcher
    }

    foreach ($f in $withJars) {
        Write-Section "$(Get-LauncherName $f)  $(Get-ShortPath $f)"
        $cfRecords = Get-CurseForgeRecords $f
        $here = @($jars | Where-Object { $_.Folder -eq $f } | Sort-Object { $_.File.Name })

        foreach ($j in $here) {
            $name = $j.File.Name
            $where = Get-InstanceLabel $f
            if ($j.Hash -and $flagged.ContainsKey($j.Hash)) {
                # Published on Modrinth/Megabase/CurseForge, but it is a cheat or PvP macro.
                $totalCheat++
                $why = "$($known[$j.Hash]): $($flagged[$j.Hash])"
                $allList.Add([ordered]@{ Status = 'CHEAT'; Name = $name; Title = $why; Where = $where })
                Write-Host "  [CHEAT] $name" -ForegroundColor Red
                Write-Host "          known as $($known[$j.Hash]), but: $($flagged[$j.Hash])" -ForegroundColor Magenta
                Write-Host "          sha1: $($j.Hash)" -ForegroundColor DarkGray
                $cheatList.Add([PSCustomObject]@{ Name = $name; Where = $where; Strings = $why })
                continue
            }
            if ($j.Hash -and $known.ContainsKey($j.Hash)) {
                $totalVerified++
                $allList.Add([ordered]@{ Status = 'OK'; Name = $name; Title = [string]$known[$j.Hash]; Where = $where })
                Write-Host ('  [OK]    {0,-32}' -f $known[$j.Hash]) -ForegroundColor Green -NoNewline
                Write-Host $name -ForegroundColor DarkGray
                continue
            }
            $hits = $null
            if ($j.Hash) { $hits = $scanned[$j.Hash] }
            $strongHit = $hits -and @($hits | Where-Object { $_.Strong }).Count -gt 0
            $client = $null
            if ($hits -and $hits.Count -gt 0 -and -not $strongHit) { $client = Get-KnownClient $j.File }
            if ($client) {
                # Legit client file; only common words like "Velocity" matched.
                $totalVerified++
                $allList.Add([ordered]@{ Status = 'OK'; Name = $name; Title = $client; Where = $where })
                Write-Host ('  [OK]    {0,-32}' -f $client) -ForegroundColor Green -NoNewline
                Write-Host $name -ForegroundColor DarkGray
            } elseif ($hits -and $hits.Count -gt 0 -and -not $strongHit) {
                # Only common words (Velocity, Hitboxes...) - a lead, not proof.
                $totalCheck++
                $allStrings = @($hits | ForEach-Object { $_.Strings } | Select-Object -Unique)
                $allList.Add([ordered]@{ Status = 'CHECK'; Name = $name; Title = "common words: $($allStrings -join ', ')"; Where = $where })
                Write-Host "  [CHECK] $name" -ForegroundColor Yellow
                Write-Host "          common words only: " -ForegroundColor Gray -NoNewline
                Write-Host ($allStrings -join ', ') -ForegroundColor DarkYellow
                Write-Host "          sha1: $($j.Hash)" -ForegroundColor DarkGray
                $checkList.Add([PSCustomObject]@{ Name = $name; Where = (Get-InstanceLabel $f); Strings = ($allStrings -join ', ') })
            } elseif ($hits -and $hits.Count -gt 0) {
                $totalCheat++
                $allList.Add([ordered]@{ Status = 'CHEAT'; Name = $name; Title = (@($hits | ForEach-Object { $_.Strings } | Select-Object -Unique) -join ', '); Where = $where })
                Write-Host "  [CHEAT] $name" -ForegroundColor Red
                foreach ($hit in $hits) {
                    Write-Host "          $($hit.Where): " -ForegroundColor Gray -NoNewline
                    Write-Host ($hit.Strings -join ', ') -ForegroundColor Magenta
                }
                Write-Host "          sha1: $($j.Hash)" -ForegroundColor DarkGray
                $allStrings = @($hits | ForEach-Object { $_.Strings } | Select-Object -Unique)
                $cheatList.Add([PSCustomObject]@{ Name = $name; Where = (Get-InstanceLabel $f); Strings = ($allStrings -join ', ') })
            } elseif ($cfRecords.ContainsKey($name) -and (-not $cfRecords[$name].Length -or [int64]$cfRecords[$name].Length -eq $j.File.Length)) {
                # Installed by the CurseForge app and no cheat names inside.
                $totalCf++
                $allList.Add([ordered]@{ Status = 'CF'; Name = $name; Title = [string]$cfRecords[$name].Name; Where = $where })
                Write-Host ('  [CF]    {0,-32}' -f $cfRecords[$name].Name) -ForegroundColor Cyan -NoNewline
                Write-Host $name -ForegroundColor DarkGray
            } else {
                $totalUnknown++
                $allList.Add([ordered]@{ Status = 'UNKNOWN'; Name = $name; Title = ''; Where = $where })
                $unknownList.Add([PSCustomObject]@{ Name = $name; Where = (Get-InstanceLabel $f) })
                Write-Host "  [?]     $name" -ForegroundColor DarkYellow
                $zone = Get-ZoneIdentifier $j.File.FullName
                if ($zone) { Write-Host "          downloaded from $zone" -ForegroundColor DarkGray }
            }
        }
        Write-Host
    }

    Write-Section 'Summary'
    Write-Host "  Verified: $totalVerified" -ForegroundColor Green
    if ($totalCf -gt 0) { Write-Host "  CF app:   $totalCf  (installed by the CurseForge app, no cheat names found)" -ForegroundColor Cyan }
    Write-Host "  Unknown:  $totalUnknown" -ForegroundColor DarkYellow
    if ($totalCheck -gt 0) { Write-Host "  Check:    $totalCheck  (only common words like Velocity - look at these by hand)" -ForegroundColor Yellow }
    Write-Host "  Cheat:    $totalCheat"   -ForegroundColor $(if ($totalCheat -gt 0) { 'Red' } else { 'Gray' })
    if ($Offline) { Write-Host '  (offline mode - no online lookups were made)' -ForegroundColor DarkGray }

    if ($cheatList.Count -gt 0) {
        Write-Host
        Write-Section "Cheats found ($($cheatList.Count))"
        foreach ($group in ($cheatList | Group-Object Where)) {
            Write-Host "  $($group.Name)" -ForegroundColor White
            foreach ($c in $group.Group) {
                Write-Host "    [CHEAT] $($c.Name)  " -ForegroundColor Red -NoNewline
                Write-Host $c.Strings -ForegroundColor Magenta
            }
        }
    }
    if ($checkList.Count -gt 0) {
        Write-Host
        Write-Section "Worth a look ($($checkList.Count))"
        foreach ($group in ($checkList | Group-Object Where)) {
            Write-Host "  $($group.Name)" -ForegroundColor White
            foreach ($c in $group.Group) {
                Write-Host "    [CHECK] $($c.Name)  " -ForegroundColor Yellow -NoNewline
                Write-Host $c.Strings -ForegroundColor DarkYellow
            }
        }
    }
    Write-Host
    Write-Host 'Unknown does not mean cheat - it just is not on Modrinth/Megabase/CurseForge. CHECK means only common words' -ForegroundColor DarkGray
    Write-Host 'like Velocity matched. Cheat hits are clear cheat names. Check them all by hand.' -ForegroundColor DarkGray

    $script:RunReport.Mods = [ordered]@{
        Folders  = @($withJars | ForEach-Object { Get-InstanceLabel $_ })
        Verified = $totalVerified; CurseForgeApp = $totalCf; Unknown = ($totalUnknown + $totalCheck); Cheat = $totalCheat
        Cheats   = @($cheatList | ForEach-Object { [ordered]@{ Name = $_.Name; Where = $_.Where; Strings = $_.Strings } })
        All      = $allList.ToArray()
        Unknowns = @(@($checkList | ForEach-Object { [ordered]@{ Name = "$($_.Name) (CHECK - common words: $($_.Strings))"; Where = $_.Where } }) +
                     @($unknownList | ForEach-Object { [ordered]@{ Name = $_.Name; Where = $_.Where } }))
    }
}

# Replace the Windows user folder and user name so reports don't show them.
function Remove-UserInfo($obj) {
    $json = $obj | ConvertTo-Json -Depth 8 -Compress
    foreach ($v in @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA)) {
        if ($v) { $json = $json.Replace(($v | ConvertTo-Json).Trim('"'), $(if ($v -eq $env:USERPROFILE) { '~' } elseif ($v -eq $env:APPDATA) { '%APPDATA%' } else { '%LOCALAPPDATA%' })) }
    }
    # any other "\Users\<name>" left in a path (other drives, other accounts)
    $json = [regex]::Replace($json, '(?i)(\\\\Users\\\\)[^\\"]+', '$1<user>')
    return $json
}

function Send-Report {
    if ($NoSend) { return }
    $modeName = @{ mods = 'Mod Analyzer'; injection = 'Injection Checker'; system = 'System Check'; full = 'Full Screenshare' }[$Mode]
    $accounts = @($script:RunReport.Accounts)
    if ($accounts.Count -eq 0) { try { $set = Get-MinecraftAccountNames; $accounts = @($set | Sort-Object) } catch {} }
    $report = [ordered]@{
        tool = 'ModAnzer'; mode = $modeName; finished = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        accounts = $accounts; mods = $script:RunReport.Mods
        system = $script:RunReport.System; injection = $script:RunReport.Injection
    }
    if ($ReportOut) {
        [IO.File]::WriteAllText($ReportOut, (Remove-UserInfo $report), (New-Object Text.UTF8Encoding($false)))
        return
    }
    Write-Host
    Write-Host "Send these results to $ReportServerName staff? Close this window to not send." -ForegroundColor White
    if (-not $NoPause) { Read-Host 'Press Enter to send and get your code' | Out-Null }
    Write-Host "[*] Sending..." -ForegroundColor Yellow -NoNewline
    try {
        $body = '{"report":' + (Remove-UserInfo $report) + '}'
        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
        $resp = Invoke-RestMethod -Uri $ReportUrl -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -UseBasicParsing -UserAgent $UserAgent -TimeoutSec 30
        Write-Host "`r[+] Sent.                    " -ForegroundColor Green
        if ($resp.code) {
            Write-Host
            Write-Host "    Your code: " -ForegroundColor White -NoNewline
            Write-Host "$($resp.code)" -ForegroundColor Yellow
            Write-Host "    Give this code to $ReportServerName staff. Only staff can see your results with it." -ForegroundColor Gray
            try { Set-Clipboard -Value "$($resp.code)" -ErrorAction Stop; Write-Host '    (copied to your clipboard)' -ForegroundColor DarkGray } catch {}
        }
    } catch {
        $msg = $_.Exception.Message
        try { if ($_.ErrorDetails.Message) { $msg = ($_.ErrorDetails.Message | ConvertFrom-Json).error } } catch {}
        Write-Host "`r[!] Could not send the results: $msg                    " -ForegroundColor Red
        Write-Host '    Take a screenshot of this window for staff instead.' -ForegroundColor DarkGray
    }
}

switch ($Mode) {
    'mods'      { Invoke-ModAnalyzer }
    'injection' { Start-InjectionChecker }
    'system'    { Invoke-SystemCheck }
    'full'      {
        Invoke-ModAnalyzer
        Write-Host; Write-Host ('=' * 70) -ForegroundColor DarkGray; Write-Host
        Invoke-SystemCheck
        Write-Host ('=' * 70) -ForegroundColor DarkGray; Write-Host
        Start-InjectionChecker
    }
}
Send-Report
Wait-BeforeClose
