using System;

namespace ThreatChecker
{
    class SClass
    {
        public static bool Malicious = false;
        public static bool Complete = false;

        public virtual byte[] HalfSplitter(byte[] originalarray, int lastgood)
        {
            var splitArray = new byte[(originalarray.Length - lastgood) / 2 + lastgood];

            if (originalarray.Length == splitArray.Length + 1)
            {
                var msg = string.Format("Identified end of matching bytes at offset 0x{0:X8}", originalarray.Length);
                CustomConsole.WriteThreat(msg);
                var msg_lastgood = string.Format("Last known good offset: 0x{0:X8}", lastgood);
                CustomConsole.WriteThreat(msg_lastgood);

                //byte[] offendingBytes = new byte[256];
                byte[] SuspectedBytes = new byte[originalarray.Length - lastgood];

                // TODO: Fix Debug output (align the array properly, account for different sizes, output a range of bytes around the suspected bytes)
                //if (originalarray.Length < 256)
                //{
                //    Array.Resize(ref offendingBytes, originalarray.Length);
                //    Buffer.BlockCopy(originalarray, originalarray.Length, offendingBytes, 0, originalarray.Length);
                //}
                //else
                //{
                    //Buffer.BlockCopy(originalarray, originalarray.Length - lastgood, offendingBytes, 0, 256);
                //    Buffer.BlockCopy(originalarray, lastgood, SuspectedBytes, 0, SuspectedBytes.Length);
                //}
                Buffer.BlockCopy(originalarray, lastgood, SuspectedBytes, 0, SuspectedBytes.Length);

                CustomConsole.WriteThreat("Printing suspect bytes:\n");
                var msg_suspected = string.Format("\nByte Count: {0}\noffset range:\n0x{1:X8}\n0x{2:X8}\n", SuspectedBytes.Length, lastgood, originalarray.Length);
                CustomConsole.WriteOutput(msg_suspected);
                var hexdump_suspected = Helpers.FormatAsHex(SuspectedBytes);
                Console.WriteLine(hexdump_suspected);

                //if (Program.Options.Debug)
                //{
                //    var msg_print = string.Format("Printing 256 bytes starting at last good offset 0x{0:X8}\n", lastgood);
                //    CustomConsole.WriteOutput(msg_print);

                //    var hexdump = Helpers.FormatAsHex(offendingBytes);
                //    Console.WriteLine(hexdump.ToString());
                //}

                Complete = true;
            }

            Array.Copy(originalarray, splitArray, splitArray.Length);
            return splitArray;
        }

        public virtual byte[] Overshot(byte[] originalarray, int splitarraysize)
        {
            var newsize = (originalarray.Length - splitarraysize) / 2 + splitarraysize;

            if (newsize.Equals(originalarray.Length - 1))
            {
                Complete = true;

                if (Malicious)
                {
                    CustomConsole.WriteError("File is signatured, but couldn't identify matching bytes");
                }
            }

            var newarray = new byte[newsize];
            Buffer.BlockCopy(originalarray, 0, newarray, 0, newarray.Length);

            return newarray;
        }
    }
}
