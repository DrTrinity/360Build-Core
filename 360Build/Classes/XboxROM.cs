using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using RC4Cryptography;
using System.Security.Cryptography;
using static _360Build.ConsoleLogger;

namespace _360Build
{
    internal class XboxNANDImage : XboxROM
    {
        public void Build()
        {

        }
    }

    internal class XboxUpdateROM : XboxROM
    {
        public void Build()
        {

        }
    }


    internal class XboxShadowbootROM : XboxROM
    {
        public void Build()
        {

        }
    }


    internal class XboxROM
    {
        internal class XboxROMHeader
        {

            public int Magic { get; set; }
            public int Length { get; set; }
            public int Version { get; set; }
            public int QFE { get; set; }
            public int Flags { get; set; }
            public int _2BLOffset { get; set; }
            public int _6BLOffset { get; set; }
            public byte[] Copyright_Info { get; set; }
            public int _6BLOffset2 { get; set; }
            public int KVLength { get; set; }
            public int KVOffset { get; set; }
            public int SMCConfigOffset { get; set; }
            public int SMCOffset { get; set; }
            public int SMCLength { get; set; }
            public int NumOfPatchslots { get; set; }
            public int KVVersion { get; set; }
            public int PatchslotSize { get; set; }

        }

        public byte[] CPUKey { get; set; }
        public byte[] Data { get; set; }

        public XboxROMHeader Header = new XboxROMHeader();
        public SMC _SMC; //SMC Firmware
        public List<Bootloader> Bootloaders = new List<Bootloader>();

        public XboxROM(string path, string cpukey)
        {
            CPUKey = Utils.StringToByteArray(cpukey);
            Data = File.ReadAllBytes(path);

            Load();
        }

        public XboxROM(string path)
        {
            Data = File.ReadAllBytes(path);

            Load();
        }

        public XboxROM()
        {

        }

        //I know. Its a mess :)
        public void Load()
        {

            //Set Variables
            Header.Version = Utils.GetInt(Data, 0x2, 2);
            Header.QFE = Utils.GetInt(Data, 0x4, 2);
            Header.Flags = Utils.GetInt(Data, 0x6, 2);
            Header.Length = Data.Length;
            Header._2BLOffset = Utils.GetInt(Data, 0x8, 4);
            Header._6BLOffset = Utils.GetInt(Data, 0xC, 4);
            Header.Copyright_Info = Utils.GetBytes(Data, 0x10, 0x40);
            Header.KVLength = Utils.GetInt(Data, 0x60, 4);
            Header._6BLOffset2 = Utils.GetInt(Data, 0x64, 4);
            Header.NumOfPatchslots = Utils.GetInt(Data, 0x68, 2);
            Header.KVVersion = Utils.GetInt(Data, 0x6A, 2);
            Header.KVOffset = Utils.GetInt(Data, 0x6C, 4);
            Header.PatchslotSize = Utils.GetInt(Data, 0x70, 4);
            Header.SMCConfigOffset = Utils.GetInt(Data, 0x74, 4);
            Header.SMCOffset = Utils.GetInt(Data, 0x7C, 4);
            Header.SMCLength = Utils.GetInt(Data, 0x78, 4);

            PrintInfo($"Loading XboxROM. Version: {Header.Version}");

            if (Header.QFE != 0)
            {
                PrintDebug($"QFE populated. ROM seems to be non-retail");
            }

            //Strip ECC
            // PrintDebug("Stripping ECC data...");
            // Data = Utils.UnEcc(Data);

            //SMC Load and Decryption
            _SMC = new SMC(Data, Header.SMCOffset, Header.SMCLength);
            _SMC.Decrypt();
            PrintInfo($"SMC Firmware Found: Version: {_SMC.VersionMajor}.{_SMC.VersionMinor.ToString("D2")}");

            LoadBootloaders();
        }
        private void LoadBootloaders()
        {
            Bootloaders = new List<Bootloader>();

            int offset = Header._2BLOffset;
            while (Enum.IsDefined(typeof(Bootloader.BootloaderType), (UInt16)Utils.GetInt(Data, offset, 2)))
            {
                Bootloader bl = new Bootloader(Data, offset);
                Bootloaders.Add(bl);
                offset += bl.Length;
            }

            offset = Header._6BLOffset;
            while (Enum.IsDefined(typeof(Bootloader.BootloaderType), (UInt16)Utils.GetInt(Data, offset, 2)))
            {
                Bootloader bl = new Bootloader(Data, offset);
                Bootloaders.Add(bl);
                offset += bl.Length;
            }

            offset = Header._6BLOffset + Header.PatchslotSize;
            while (Enum.IsDefined(typeof(Bootloader.BootloaderType), (UInt16)Utils.GetInt(Data, offset, 2)))
            {
                Bootloader bl = new Bootloader(Data, offset);
                Bootloaders.Add(bl);
                offset += bl.Length;
            }

            foreach (var (i, bl) in Bootloaders.Select((bldr, idx) => (idx, bldr)))
            {

                PrintInfo($"Bootloader found: {bl.Type} {bl.Version}. Decrypting...");

                if (i != 0)
                {
                    if ((i == 1) && bl.Type == Bootloader.BootloaderType.CB)
                    {
                        bl.Decrypt(Bootloaders[i - 1], CPUKey);
                    }
                    else if (bl.Type == Bootloader.BootloaderType.CF)
                        bl.Decrypt(null, CPUKey);
                    else
                    {
                        bl.Decrypt(Bootloaders[i - 1]);
                    }
                }
                else
                {
                    bl.Decrypt();
                }
            }
        }

    }
}
