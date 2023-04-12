using CommandLine;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace ThreatChecker
{
    class Program
    {
        public class Options
        {
            [Option('d', "debug", Required = false, HelpText = "Enable debug output")]
            public static bool Debug { get; set; }

            [Option('e', "engine", Default = "DClass", Required = false, HelpText = "Scanning engine. Options: DClass, AMSI")]
            public string Engine { get; set; }

            [Option('f', "file", Required = false, HelpText = "Analyze a file on disk")]
            public string InFile { get; set; }

            [Option('u', "url", Required = false, HelpText = "Analyze a file from a URL")]
            public string InUrl { get; set; }
        }

        public enum ScanningEngine
        {
            DClass,
            Amsi
        }

        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptions)
                .WithNotParsed(HandleParseError);
        }

        public static void RunOptions(Options opts)
        {
            var file = new byte[] { };
            var engine = (ScanningEngine)Enum.Parse(typeof(ScanningEngine), opts.Engine, true);

            if (!string.IsNullOrEmpty(opts.InUrl))
            {
                try
                {
                    file = DownloadFile(opts.InUrl);
                }
                catch
                {
                    CustomConsole.WriteError("Could not connect to URL");
                    return;
                }

            }
            else if (!string.IsNullOrEmpty(opts.InFile))
            {
                if (File.Exists(opts.InFile))
                {
                    file = File.ReadAllBytes(opts.InFile);
                }
                else
                {
                    CustomConsole.WriteError("File not found");
                    return;
                }
            }
            else
            {
                CustomConsole.WriteError("File or URL required");
                return;
            }

            switch (engine)
            {
                case ScanningEngine.DClass:
                    ScanWithDefender(file);
                    break;
                case ScanningEngine.Amsi:
                    ScanWithAmsi(file);
                    break;
                default:
                    break;
            }
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {
            foreach (Error err in errs)
            {
                Console.Error.WriteLine(err.ToString());
            }
        }

        static byte[] DownloadFile(string url)
        {
            using (var client = new WebClient())
            {
                return client.DownloadData(url);
            }
        }

        static void ScanWithDefender(byte[] file)
        {
            var defender = new DClass(file);
            defender.AnalyzeFile();
        }

        static void ScanWithAmsi(byte[] file)
        {
            using (var amsi = new AIClass())
            {
                //if (!amsi.RealTimeProtectionEnabled)
                //{
                //    CustomConsole.WriteError("Ensure real-time protection is enabled");
                //    return;
                //}

                amsi.AnalyzeBytes(file);
            }
        }
    }
}
