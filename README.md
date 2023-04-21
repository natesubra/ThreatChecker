# ThreatCheck(er)

A updated/modified version of ThreatCheck/DefenderCheck. Full credit to [Matterpreter](https://github.com/matterpreter/DefenderCheck)/[Rastamouse](https://github.com/rasta-mouse/ThreatCheck) for the initial implementation(s) and ideas.

---

Takes a binary as input (either from a file on disk or a URL), splits it until it pinpoints that exact bytes that the target engine will flag on and prints them to the screen. This can be helpful when trying to identify the specific bad pieces of code in your tool/payload.

Changes:

- Refactored output: Now attempts to identify and print the range of suspect bytes
- New HexDump function
- Added GitHub CI/CD Release
- Added an arg to enable debug output, for when you want to watch text scroll fast
- Refactored some things that were getting flagged by AV in the OG ThreatCheck
- Dependencies:
  - added new deps required for hexdump
  - added [Costura.Fodya] to allow the exe to be self contained (embedded assemblies)
  - updated deps to latest stable

Todo:

- Fix the debug display showing the full byte range AROUND the suspect bytes
- Implement additional logic for corner cases
- ??? (Pull requests accepted)

```text
C:\>ThreatChecker.exe --help
  -d, --debug     Enables debug output
  -e, --engine    (Default: Defender) Scanning engine. Options: Defender, AMSI
  -f, --file      Analyze a file on disk
  -u, --url       Analyze a file from a URL
  --help          Display this help screen.
  --version       Display version information.
```

## Example

```text
C:\Users\temp\Desktop\TC>ThreatChecker.exe -f c:\av-exclusions\x64.exe
[+] Target file size: 339456 bytes
[+] Analyzing...
[!] Identified end of matching bytes at offset 0x00000C1D
[!] Last known good offset: 0x00000C1B
[!] Printing suspect bytes:

[+]
Byte Count: 2
offset range:
0x00000C1B
0x00000C1D

00000000 7F E9                                           ..
```

## Configuring Defender/Workflow

I recommend running the following PowerShell commands (as an Administrator) to prep your testing device

```PowerShell
# Required for AMSI to work properly
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableScriptScanning $false
# Disable automatic uploads/submissions
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent NeverSend
# Set default actions to NoAction allows stuff to be flagged without defender killing the calling process and without quarantining the file
Set-MpPreference -LowThreatDefaultAction NoAction
Set-MpPreference -ModerateThreatDefaultAction NoAction
Set-MpPreference -HighThreatDefaultAction NoAction
Set-MpPreference -SevereThreatDefaultAction NoAction
Set-MpPreference -UnknownThreatDefaultAction Noaction
# Newer versions of mpcmdrun allow for scanning of excluded items, drop your things here to facilitate more rapid testing
$dir = New-Item -Path C:\ -Name "av-exclusions" -Force -Verbose -Type Directory
Set-MpPreference -ExclusionPath $dir.FullName
```

1. Copy artifacts to test to `C:\av-exclusions`
2. Run ThreatChecker against said artifacts: `ThreatChecker.exe 
3. ???
4. Test again with ThreatChecker

## Compiling your own

Grab the latest visual studio community or visual studio build kit

1. Open a visual studio terminal prompt
2. Clone the project `git clone https://github.com/natesubra/ThreatChecker`
3. `cd ThreatChecker\ThreatChecker`
4. run msbuild:

   ```shell
    msbuild -target:clean
    msbuild -restore
    msbuild -m -"Property:Configuration=Release,Platform=Any CPU"
   ```
