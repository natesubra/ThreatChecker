# ThreatCheck(er)

A updated/modified version of ThreatCheck/DefenderCheck

Changes:

- Refactored output: Now attempts to identify the range of suspect bytes
- Re-enabled debug output, for when 
- Refactored some things that were getting flagged by AV (this probably won't last long, class names IIRC)
- Added GitHub CI/CD Release
- Updated dependencies etc
## Credits

- Modified version of [RastaMouse's](https://rastamouse.me/) [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)
- Which in turn is a modified version of [Matterpreter's](https://twitter.com/matterpreter) [DefenderCheck](https://github.com/matterpreter/DefenderCheck).

Takes a binary as input (either from a file on disk or a URL), splits it until it pinpoints that exact bytes that the target engine will flag on and prints them to the screen. This can be helpful when trying to identify the specific bad pieces of code in your tool/payload.

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
$dir = New-Item -Path C:\ -Name "av-exclusions" -Force -Verbose
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
