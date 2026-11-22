# ModAnzer for RyftTiers

RyftTiers' copy of [PrimeTiers/ModAnzer](https://github.com/PrimeTiers/ModAnzer). A Minecraft mod analyzer for Windows. It finds every mods folder on the PC by itself, so there is no path to paste, then checks each mod against Modrinth and Megabase and scans unknown mods for cheat module names.

Based on [HabibiModAnalyzer](https://github.com/HadronCollision/PowershellScripts) by HadronCollision.

## Website

**https://ryfttiers-modanzer.onrender.com** has the download buttons, the one-liner, and what the tools do and don't do. It's a Render static site built from this repo (`site/index.html`), and it updates on every push to `main`.

Shortest way to run it:

```powershell
powershell -ExecutionPolicy Bypass -NoProfile -Command "iex ((irm https://ryfttiers-modanzer.onrender.com/ModAnzer.txt) -join [char]10)"
```

## Run it

**Easiest:** download **[ModAnzer.exe](https://github.com/RyftTiers/ModAnzer/releases/download/apk/ModAnzer.exe)** and open it. It is a small Windows app in RyftTiers colours (the same dark cards, blue accent and orange warnings as the RyftTiers queue cards): pick a check, press **Start scan**, then press **Get code** and give the code to staff. It runs the same `ModAnzer.ps1` (built into the exe) with Windows PowerShell 5.1 and needs .NET Framework 4.8, which Windows 10 and 11 already have. The source is in [`exe/`](exe). If Windows SmartScreen appears, click **More info → Run anyway**.

**Or:** download **[ModAnzer.bat](https://github.com/RyftTiers/ModAnzer/releases/download/apk/ModAnzer.bat)** and double-click it. It runs the `ModAnzer.ps1` next to it if there is one, and otherwise downloads the latest version from the website. If Windows SmartScreen appears, click **More info → Run anyway**.


**Easiest way:** download `ModAnzer.ps1`, right-click it and choose **Run with PowerShell**. If Windows asks whether to run a downloaded script, choose **Run once**. The window stays open at the end until you press Enter.

**From a PowerShell window:**

1. Download **[ModAnzer.ps1](https://github.com/RyftTiers/ModAnzer/releases/download/apk/ModAnzer.ps1)** from the latest release. If you like, check it against `SHA256SUMS.txt` on the [release page](https://github.com/RyftTiers/ModAnzer/releases/tag/apk).
2. Open PowerShell in the folder you saved it to and run:

```powershell
Unblock-File .\ModAnzer.ps1
powershell -NoProfile -ExecutionPolicy RemoteSigned -File .\ModAnzer.ps1
```

`Unblock-File` tells Windows you trust the file you downloaded. `RemoteSigned` applies only to this one run and doesn't change any settings.

Please don't run it with a pasted `irm ... | iex` one-liner. Downloading code and running it straight from memory with the execution policy bypassed is exactly how malware gets in, so antivirus tools watch for that pattern and may block or flag it. Running a saved file avoids that, and you can read the file before running it.

### Desktop shortcut

To start it with a double-click, download **[ModAnzer.ico](https://github.com/RyftTiers/ModAnzer/releases/download/apk/ModAnzer.ico)** and put it next to `ModAnzer.ps1`. Then:

1. Right-click the desktop and choose **New → Shortcut**.
2. For the location, enter the following, changing the path to where you saved the script:
   ```
   powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "C:\Users\you\Downloads\ModAnzer\ModAnzer.ps1"
   ```
3. Name it **ModAnzer** and click **Finish**.
4. Right-click the shortcut and choose **Properties → Change Icon → Browse**, then pick `ModAnzer.ico`.

Make the shortcut on each PC rather than sending a `.lnk` file to someone. A shortcut only points to files on the PC it was made on, so the receiver gets a broken shortcut with no icon. Discord and antivirus tools also often block shortcut files that start PowerShell, because malware spreads that way. To share it, send the [release page](https://github.com/RyftTiers/ModAnzer/releases/tag/apk) link instead.

## What it can do

When it starts, the script asks what to do:

```
  1) Mod Analyzer       - check the mods in your mods folders  [default]
  2) Injection Checker  - check the running game, its memory, and watch it live
  3) System Check       - traces: programs that ran, deleted files, cleared logs, USB
  4) Full Screenshare   - all three, one after another
```

For options 2–4 it offers to restart as **administrator**. The player can say no; it then runs the checks a normal user can see and says which ones it skipped.

### Injection Checker

Run it while the player is in Minecraft (Windows only):

1. **Launch options:** flags anything that adds code at startup, such as `-javaagent`, `-agentpath`, `fabric.addMods`/`loadMods`, the Java debugger, or `-noverify`. Lunar uses its own Java agents, so check where an agent's file lives before calling it a cheat.
2. **Loaded DLLs:** flags Java agent support (`instrument.dll`), the debugger (`jdwp.dll`), DLLs loaded from Downloads/Desktop/Temp, and unsigned DLLs. Signed overlays (Discord, OBS, NVIDIA, Steam) show as "worth a look".
3. **Game memory (read-only):** reads Minecraft's memory and flags cheat module and client names (KillAura, AutoCrystal, Meteor, Wurst, LiquidBounce...), plus **hidden programs**: a complete DLL/EXE sitting in the game's private memory with no file behind it, which is how "manual-mapped" cheats hide from file scans. A cheat name can also be in memory because someone typed it in chat, so check the context.
4. **Live watch:** alerts the moment a DLL is injected or a flagged one unloads, a mod is added or removed, or a program starts from Downloads/Desktop/Temp. Press **Q** to stop and see the summary.

### System Check

Looks for traces of cheating on the PC (Windows only):

| Check | What it looks for | Needs admin |
|---|---|---|
| PC and running programs | recent restart, virtual machine, cheat tools running now (Cheat Engine, Process Hacker, injectors, macro tools...) | no |
| Logging services | EventLog, SysMain (Prefetch), PcaSvc, DiagTrack or BAM turned off | no |
| Programs that ran (BAM) | last 24 h: cheat tools, programs that ran and were then **deleted**, unsigned programs from Downloads/Desktop/Temp | **yes** |
| Prefetch | cheat tools that ran in the last 24 h, an emptied or freshly cleared Prefetch folder | **yes** |
| PowerShell history | clearing history or event logs, deleting mods/`.jar`/Prefetch, antivirus exclusions, stopping logging services, downloading `.jar`/`.dll`/`.exe` | no |
| Event logs | logs cleared in the last 7 days (System 104, Security 1102), file change journal deleted (3079) | Security log only |
| USB drives | drives plugged in now or in the last 24 h | no |
| Deleted and downloaded files | `.jar`/`.dll`/`.exe`/`.ahk` in the Recycle Bin, recent mods and tools in Downloads/Desktop | no |
| Minecraft accounts | account **names** from launcher files and game logs, to spot alts. Never tokens or emails | no |

Everything is a lead, not proof. Check each one with the player.

### Sending results to staff

When the scan ends, ModAnzer shows **"Press Enter to send and get your code"** (in the app: the **Get code** button). Sending saves the results on ModAnzer's server and shows a 6-character code, like `7k3qxf`. The player gives the code to staff, and staff run `/ssresult refcode:7k3qxf user:@player` in the RyftTiers bot to see the report. Closing the window instead sends nothing. Use `-NoSend` to skip this, or `-NoPause` to send without asking.

- Reports go to ModAnzer's server ([`supabase/functions/modanzer-report`](supabase/functions/modanzer-report/index.ts)), which saves them in the RyftTiers Supabase database, in the `modanzer_reports` table, under a random reference code. Nothing is posted until staff look the code up with `/ssresult`.
- The server keeps only the fields ModAnzer sends, and caps their sizes. It rate-limits each sender to 6 reports a minute and doesn't store IP addresses.
- Windows user folders are shown as `~` and user names as `<user>`. Minecraft account **names** are included, never tokens or emails.

Setup, in the **RyftTiers** Supabase project:

1. Create the table by running [`supabase/modanzer_reports.sql`](supabase/modanzer_reports.sql) in the SQL editor.
2. Deploy `supabase/functions/modanzer-report` with **JWT verification off** (`supabase functions deploy modanzer-report --no-verify-jwt`). It uses the `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` Supabase gives every function, so there are no secrets to add.

Saved row in `modanzer_reports` (JSON columns shown as JSON):

```json
{
  "tool": "ModAnzer", "mode": "Full Screenshare", "finished": "2026-11-21 09:30:00 +07:00",
  "ref_code": "7k3qxf", "accounts": ["Steve"],
  "mods": { "Folders": [], "Verified": 0, "CurseForgeApp": 0, "Unknown": 0, "Cheat": 0, "Cheats": [{ "Name": "", "Where": "", "Strings": "" }], "Unknowns": [{ "Name": "", "Where": "" }] },
  "system":    { "Admin": true, "Alerts": [{ "Time": "09:20", "Level": "Red", "Text": "" }] },
  "injection": { "Admin": true, "Uptime": "", "GameFolder": "", "Alerts": [] },
  "status": "new", "received_at": "<date>", "sender_hash": "<16 hex>",
  "checked_by": null, "checked_at": null, "player_id": null
}
```

### Antivirus

The Mod Analyzer and System Check only read files, logs and the registry. The **memory scan** is different: to read Minecraft's memory, the script compiles a small built-in helper (it's in the script, look for `ModAnzerNative`) that uses the Windows functions for reading another program's memory. That's what cheats and malware use too, so **Windows Defender may flag or block the script**. The helper is only compiled when the Injection Checker or System Check runs, it only opens Minecraft for reading, and it never writes to, suspends or injects into any process. If the helper gets blocked, ModAnzer skips the memory scan and carries on.

Use `-Mode mods|injection|system|full` to skip the menu, and `-LiveSeconds 300` to stop the live watch on its own after 5 minutes.

When it starts, it first shows what it does and doesn't do, and waits for you to press Enter. The Mod Analyzer then asks which launcher you use:

```
  1) Scan everything (auto-detect)  [default]
  2) Minecraft Launcher (.minecraft, Badlion, SKLauncher)
  3) CurseForge
  4) Modrinth App
  5) Prism / MultiMC / PolyMC
  6) ATLauncher
  7) GDLauncher
  8) Lunar Client
  9) Dawn Client (formerly Feather)
 10) Fast Client
 11) TLauncher
 12) Technic
 13) Other (type the path to your mods folder)
```

Press Enter for 1. If the launcher you pick has no mods folder in its usual place, it asks you to paste the path, or press Enter to scan everything.

### Options

| Option | What it does |
|---|---|
| `-Path "D:\pack\mods"` | Skip the menu and scan only these folders (can list several, comma-separated) |
| `-Offline` | Skip the online lookups; only do the cheat-string scan |
| `-SkipIntro` | Don't show the "what this script does" notice at the start |
| `-Mode mods` / `injection` / `system` / `full` | Skip the start menu and go straight to that option |
| `-NoPause` | Don't wait for Enter before closing at the end |

## Where it looks

- Vanilla launcher: `%APPDATA%\.minecraft` (including the Microsoft Store version)
- CurseForge: `~\curseforge\minecraft\Instances\*`
- Modrinth App: `%APPDATA%\ModrinthApp\profiles\*`
- Prism, PolyMC, MultiMC, ATLauncher, GDLauncher, Technic
- Fast Client (`%APPDATA%\.fastclient` and similar)
- Dawn, formerly Feather (`%APPDATA%\.dawn`, and `.feather` with its `user-mods` folder), Lunar, TLauncher
- Any dot-folder in `%APPDATA%` or your user folder, such as `.badlion`
- The game folder of any Minecraft that is running right now (read from `--gameDir`)

Jars in one level of subfolders (for example `mods\1.21\`) are included too.

## What it does

1. Hashes every `.jar` with SHA1.
2. Looks the hashes up on Modrinth in one batched request, then on Megabase and CurseForge for anything Modrinth doesn't know. Only hashes and fingerprints leave your PC, never files.
3. Checks the mods it recognised too, because cheats and PvP macros can be published on Modrinth. A recognised mod counts as **[CHEAT]** when its Modrinth slug or SHA1 is in [`flagged.txt`](flagged.txt), when its name says what it does (AutoTotem, Crystal Macro, TriggerBot, Aim Assist and so on), or when its jar has a class named like a cheat module (`AutoTotem.class`). Add a Modrinth macro to `flagged.txt` on GitHub to catch it without a new release.
4. Opens each unrecognised jar in memory, including jars nested in `META-INF/jars`, and searches it for cheat module names.
   - **Strong names** such as AutoCrystal, TriggerBot and KillAura count wherever they appear.
   - **Generic names** (Velocity, Hitboxes, AimAssist, AutoArmor, FastPlace) are also ordinary game-code words, like `getVelocity` in physics mods, so they only count when they are a whole name on their own: a class called `Velocity.class` or `VelocityModule.class`, or the exact text `Velocity` stored as a separate string. That's how cheat module names look.
5. Prints the results grouped by launcher and instance: **[OK]** verified, **[CF]** installed by the CurseForge app with no cheat names inside, **[?]** unknown (with the download URL Windows recorded, if any), and **[CHEAT]** with the strings that matched and the file's SHA1.
6. Ends with a summary and a **Cheats found** list showing every cheat and which launcher and instance it was in.

It is read-only: nothing is modified, uploaded, extracted to disk, or installed.

"Unknown" doesn't mean cheat. It only means the mod isn't on Modrinth, Megabase or CurseForge. A cheat hit is a name match, so check it by hand before acting on it.

### Trusted mods

Some legit client mods, such as FastClient HUD and Dawn, contain cheat-like names. To mark them OK, add a line to [`trusted.txt`](trusted.txt) in this repo with the SHA1 printed under the `[CHEAT]` result:

```
1807bd0592525fe40d0d0ee69d30b7486c48fdc7  FastClient HUD 1.21.11
```

You can edit the file on GitHub, even from a phone, and the script and app pick it up on their next run. Each version of a mod has its own SHA1, so add a line whenever a trusted mod updates. Mods are trusted by exact SHA1 rather than by name, so a cheat renamed to look like a trusted mod is still caught.

### CurseForge

Mods are checked against CurseForge's database by fingerprint, like they are on Modrinth and Megabase, and matches show as `[OK] Name [CurseForge]`.

CurseForge requires an API key and asks that it be kept private, so the lookups go through a small server function ([`supabase/functions/modanzer-cf`](supabase/functions/modanzer-cf/index.ts)) that holds the key. The script and app send it only CurseForge fingerprints, which are numbers. It can only do fingerprint lookups and rate-limits each IP address. The key is stored as the `CURSEFORGE_API_KEY` secret in the Supabase project, never in this repo or the downloads.

- **[CF] results** come from the CurseForge app's own install record (`minecraftinstance.json`) and still work if the server is down. They're still scanned for cheat names, so a cheat added to that record still shows as `[CHEAT]`.
- To ask CurseForge directly with your own key instead, put it in `$CurseForgeApiKey` near the top of `ModAnzer.ps1` or set the `MODANZER_CF_KEY` environment variable.

## Changes from HabibiModAnalyzer

- Automatic discovery of mods folders across launchers and clients
- One batched Modrinth request instead of two requests per mod
- Each identical jar is checked once, even if it is in several instances
- In-memory scanning with no temp folder, and nested jars inside nested jars
- Case-sensitive matching to cut false positives, with duplicate strings removed and a few added
- Uptime shown for every running instance, along with its game folder
- A launcher menu with an "Other" option for any mods folder

## Android app

There's also an Android version in [`android/`](android/). Download it here, on your phone:

**[ModAnzer.apk](https://github.com/RyftTiers/ModAnzer/releases/download/apk/ModAnzer.apk)**

Open the downloaded file to install it. Android will ask you to allow installs from your browser or file manager the first time.

In the app, tap **Pick folder** and choose your mods folder, or a whole launcher or `.minecraft` folder; every mods folder inside it gets scanned. **Pick .jar files** checks individual jars instead. For PojavLauncher and similar launchers, open the picker's side menu (☰) and choose the launcher there. It does the same checks as the PC version: Modrinth and Megabase lookups by hash, then a cheat-string scan of unknown mods, including nested jars.

The app needs only the Internet permission and reads only the files or folder you pick. It has no ads, trackers or third-party libraries.

### Signing and developer verification

GitHub builds the APK whenever something in `android/` changes and signs it with a private key stored in the repo's Actions secrets (`MODANZER_KEYSTORE_BASE64` and `MODANZER_KEYSTORE_PASSWORD`). The key is not in the repo. If the secrets are missing, the build uses a temporary key and new builds won't install over old ones.

From 30 September 2026, certified Android phones in Brazil, Indonesia, Singapore and Thailand only install apps from developers registered with Google, and other countries follow later. To keep the APK installable there, register the app's package name (`com.ryfttiers.modanzer`) and its signing key in the Android Developer Console. A free limited-distribution account allows up to 20 devices; a full account has a one-time $25 fee.

## What antivirus might say

Nothing in ModAnzer is hidden or obfuscated. The script is plain text, and the app's full source is in this repo.

- **Windows:** the memory scan is the part most likely to be flagged (see **Antivirus** above). The Mod Analyzer also lists folders in `%APPDATA%` and reads `.jar` files, which a heuristic scanner could mistake for a stealer, but it never opens tokens or passwords and sends only hashes. If Windows Defender flags it, [report a false positive to Microsoft](https://www.microsoft.com/en-us/wdsi/filesubmission).
- **Android:** Play Protect may warn about any app that doesn't come from the Play Store. Registering as a developer (above) removes that warning.

