using System;

using static ThreatChecker.NativeMethods;

namespace ThreatChecker
{
    class AIClass : SClass, IDisposable
    {
        IntPtr AmsiContext;
        IntPtr AmsiSession;

        byte[] FileBytes;

        public AIClass(string appName = "ThreatChecker")
        {
            AmsiInitialize(appName, out AmsiContext);
            AmsiOpenSession(AmsiContext, out AmsiSession);
        }

        public void AnalyzeBytes(byte[] bytes)
        {
            FileBytes = bytes;

            var status = ScanBuffer(FileBytes);

            if (status != AMSI_RESULT.AMSI_RESULT_DETECTED)
            {
                CustomConsole.WriteOutput("No signature found!");
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

                var detectionStatus = ScanBuffer(splitArray);

                if (detectionStatus == AMSI_RESULT.AMSI_RESULT_DETECTED)
                {
                    if (Program.Options.Debug)
                    {
                        CustomConsole.WriteDebug("Signature found, splitting");
                    }

                    var tmpArray = HalfSplitter(splitArray, lastgood);
                    Array.Resize(ref splitArray, tmpArray.Length);
                    Array.Copy(tmpArray, splitArray, tmpArray.Length);
                }
                else
                {

                    if (Program.Options.Debug)
                    {
                        CustomConsole.WriteDebug("No signature found, increasing size");
                    }

                    lastgood = splitArray.Length;
                    var tmpArray = Overshot(FileBytes, splitArray.Length); //Create temp array with 1.5x more bytes
                    Array.Resize(ref splitArray, tmpArray.Length);
                    Buffer.BlockCopy(tmpArray, 0, splitArray, 0, tmpArray.Length);
                }
            }
        }

        AMSI_RESULT ScanBuffer(byte[] buffer)
        {
            AmsiScanBuffer(AmsiContext, buffer, (uint)buffer.Length, "sample", AmsiSession, out AMSI_RESULT result);
            return result;
        }

        AMSI_RESULT ScanBuffer(byte[] buffer, IntPtr session)
        {
            AmsiScanBuffer(AmsiContext, buffer, (uint)buffer.Length, "sample", session, out AMSI_RESULT result);
            return result;
        }

        //public bool RealTimeProtectionEnabled
        //{
        //    get
        //    {
        //        var sample = Encoding.UTF8.GetBytes("Invoke-Expression 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'");
        //        var result = ScanBuffer(sample, IntPtr.Zero);

        //        if (result != AMSI_RESULT.AMSI_RESULT_DETECTED)
        //        {
        //            return false;
        //        }
        //        else
        //        {
        //            return true;
        //        }
        //    }
        //}

        public void Dispose()
        {
            AmsiCloseSession(AmsiContext, AmsiSession);
            AmsiUninitialize(AmsiContext);
        }
    }
}
