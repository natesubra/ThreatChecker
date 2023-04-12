using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace ThreatChecker
{
    class DClass : SClass
    {
        byte[] FileBytes;
        string FilePath;

        public DClass(byte[] file)
        {
            FileBytes = file;
        }

        public void AnalyzeFile()
        {
            if (!Directory.Exists(@"C:\MyTCTemp"))
            {
                if (Program.Options.Debug)
                {
                    CustomConsole.WriteDebug(@"C:\MyTCTemp doesn't exist. Creating it...");
                }
                Directory.CreateDirectory(@"C:\MyTCTemp");
            }

            FilePath = Path.Combine(@"C:\MyTCTemp", "MyTCTest.exe");
            File.WriteAllBytes(FilePath, FileBytes);

            var status = ScanFile(FilePath);

            if (status.Result == ScanResult.NoThreatFound)
            {
                CustomConsole.WriteOutput("No threat found!");
                return;
            }
            else
            {
                Malicious = true;
            }

            CustomConsole.WriteOutput($"Target file size: {FileBytes.Length} bytes");
            CustomConsole.WriteOutput("Analyzing...");

            var splitArray = new byte[FileBytes.Length / 2];
            Buffer.BlockCopy(FileBytes, 0, splitArray, 0, FileBytes.Length / 2);
            var lastgood = 0;

            while (!Complete)
            {
                if (Program.Options.Debug)
                {
                    CustomConsole.WriteDebug($"Testing {splitArray.Length} bytes");
                }

                File.WriteAllBytes(FilePath, splitArray);
                status = ScanFile(FilePath);

                if (status.Result == ScanResult.ThreatFound)
                {
                    if (Program.Options.Debug)
                    {
                        CustomConsole.WriteDebug("Threat found, splitting");
                    }

                    var tmpArray = HalfSplitter(splitArray, lastgood);
                    Array.Resize(ref splitArray, tmpArray.Length);
                    Array.Copy(tmpArray, splitArray, tmpArray.Length);
                }
                else if (status.Result == ScanResult.NoThreatFound)
                {

                    if (Program.Options.Debug)
                    {
                        CustomConsole.WriteDebug("No threat found, increasing size");
                    }

                    lastgood = splitArray.Length;
                    var tmpArray = Overshot(FileBytes, splitArray.Length);
                    Array.Resize(ref splitArray, tmpArray.Length);
                    Buffer.BlockCopy(tmpArray, 0, splitArray, 0, tmpArray.Length);
                }
            }
        }

        public DSResult ScanFile(string file, bool getsig = false)
        {
            var result = new DSResult();

            if (!File.Exists(file))
            {
                result.Result = ScanResult.FileNotFound;
                return result;
            }

            var process = new Process();
            var mpcmdrun = new ProcessStartInfo(@"C:\Program Files\Windows Defender\MpCmdRun.exe")
            {
                Arguments = $"-Scan -ScanType 3 -DisableRemediation -Trace -Level 0x10 -File \"{file}\"",
                CreateNoWindow = true,
                ErrorDialog = false,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            process.StartInfo = mpcmdrun;
            process.Start();
            process.WaitForExit(30000); //Wait 30s

            if (!process.HasExited)
            {
                process.Kill();
                result.Result = ScanResult.Timeout;
                return result;
            }

            if (getsig)
            {
                string stdout;
                string sigName;

                while ((stdout = process.StandardOutput.ReadLine()) != null)
                {
                    if (stdout.Contains("Threat  "))
                    {
                        string[] sig = stdout.Split(' ');
                        sigName = sig[19]; // Lazy way to get the signature name from MpCmdRun
                        result.Signature = sigName;
                        break;
                    }
                }
            }

            switch (process.ExitCode)
            {
                case 0:
                    result.Result = ScanResult.NoThreatFound;
                    break;
                case 2:
                    result.Result = ScanResult.ThreatFound;
                    break;
                default:
                    result.Result = ScanResult.Error;
                    break;
            }

            return result;
        }
    }

    public class DSResult
    {
        public ScanResult Result { get; set; }
        public string Signature { get; set; }
    }

    public enum ScanResult
    {
        [Description("No signature found")]
        NoThreatFound,
        [Description("Signature found")]
        ThreatFound,
        [Description("The file could not be found")]
        FileNotFound,
        [Description("Timeout")]
        Timeout,
        [Description("Error")]
        Error
    }
}
