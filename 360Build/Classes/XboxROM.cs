using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using RC4Cryptography;
using System.Security.Cryptography;
using static _360Build.ConsoleLogger;
using System.Buffers.Binary;
using System.Runtime.InteropServices.Marshalling;
using System.Net;

namespace _360Build
{

    internal class XboxROM
    {
        internal static class BlockSize
        {
            public const int SMALL = 0x1000;
            public const int BIG = 0x20000;
        }
        
        internal class XboxROMHeader
        {
            public int Length { get; set; }

            public short Magic { get; set; }
            public short Version { get; set; }
            public short QFE { get; set; }
            public short Flags { get; set; }
            public int _2BLOffset { get; set; }
            public int _6BLOffset { get; set; }
            public byte[] Copyright_Info { get; set; }
            public int KVLength { get; set; }
            public int _6BLOffset2 { get; set; }
            public short NumOfPatchslots { get; set; }
            public short KVVersion { get; set; }
            public int KVOffset { get; set; }
            public int PatchslotSize { get; set; }
            public int SMCConfigOffset { get; set; }
            public int SMCLength { get; set; }
            public int SMCOffset { get; set; }

            public byte[] Data
            {
                get
                {
                    using MemoryStream ms = new();

                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(Magic)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(Version)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(QFE)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(Flags)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(_2BLOffset)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(_6BLOffset)));
                    ms.Write(Copyright_Info);
                    ms.Write(new byte[0x10]);
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(KVLength)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(_6BLOffset2)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(NumOfPatchslots)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(KVVersion)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(KVOffset)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(PatchslotSize)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(SMCConfigOffset)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(SMCLength)));
                    ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(SMCOffset)));

                    return ms.ToArray();
                }
            }
        }
        

        public byte[] CPUKey { get; set; }
        public byte[] Data { get; set; }

        public XboxROMHeader Header = new XboxROMHeader();
        public SMC _SMC; //SMC Firmware
        public List<Bootloader> Bootloaders = new List<Bootloader>();


        public XboxROM(){}

        public XboxROM(string path, string cpukey) : this(path)
        {
            CPUKey = Utils.StringToByteArray(cpukey);
        }

        public XboxROM(string path)
        {
            try
            {
                Data = File.ReadAllBytes(path);
            }
            catch (FileNotFoundException ex)
            {
                PrintError($"File not found at {ex.FileName}");
                throw;
            }
            catch (Exception ex)
            {
                PrintError($"Error reading in file: {ex.Message}");
                throw;
            }

            Load();
        }

        private void Load()
        {

            //Set Header Variables
            Header.Magic = (short)Utils.GetInt(Data, 0, 2);
            Header.Version = (short)Utils.GetInt(Data, 0x2, 2);
            Header.QFE = (short)Utils.GetInt(Data, 0x4, 2);
            Header.Flags = (short)Utils.GetInt(Data, 0x6, 2);
            Header.Length = Data.Length;
            Header._2BLOffset = Utils.GetInt(Data, 0x8, 4);
            Header._6BLOffset = Utils.GetInt(Data, 0xC, 4);
            Header.Copyright_Info = Utils.GetBytes(Data, 0x10, 0x40);
            Header.KVLength = Utils.GetInt(Data, 0x60, 4);
            Header._6BLOffset2 = Utils.GetInt(Data, 0x64, 4);
            Header.NumOfPatchslots = (short)Utils.GetInt(Data, 0x68, 2);
            Header.KVVersion = (short)Utils.GetInt(Data, 0x6A, 2);
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
            while (Enum.IsDefined(typeof(Bootloader.BootloaderType), (ushort)Utils.GetInt(Data, offset, 2)))
            {
                Bootloader.BootloaderType blType = (Bootloader.BootloaderType)Utils.GetInt(Data, offset, 2);
                Bootloader bl = Bootloader.Create(Data, offset, blType);
                Bootloaders.Add(bl);
                offset += bl.Length;
            }

            // offset = Header._6BLOffset;
            // while (Enum.IsDefined(typeof(Bootloader.BootloaderType), (ushort)Utils.GetInt(Data, offset, 2)))
            // {
            //     Bootloader.BootloaderType blType = (Bootloader.BootloaderType)Utils.GetInt(Data, offset, 2);
            //     Bootloader bl = Bootloader.Create(Data, offset, blType);
            //     Bootloaders.Add(bl);
            //     offset += bl.Length;
            // }

            // offset = Header._6BLOffset + Header.PatchslotSize;
            // while (Enum.IsDefined(typeof(Bootloader.BootloaderType), (ushort)Utils.GetInt(Data, offset, 2)))
            // {
            //     Bootloader.BootloaderType blType = (Bootloader.BootloaderType)Utils.GetInt(Data, offset, 2);
            //     Bootloader bl = Bootloader.Create(Data, offset, blType);
            //     Bootloaders.Add(bl);
            //     offset += bl.Length;
            // }

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

    internal class XboxUpdateROM : XboxROM
    {
        public XboxUpdateROM() {}

        public XboxUpdateROM(string path) : base(path) {}

        public void Build(string outputPath)
        {
            PrintInfo("Building Xbox Update ROM...");

            try
            {
                using FileStream fs = new(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);

                fs.Write(Header.Data);

                fs.Write(new byte[Header.SMCOffset - fs.Length]);

                _SMC.Encrypt();
                fs.Write(_SMC.Data);

                fs.Write(new byte[Header._2BLOffset - fs.Length]);
                

                foreach (var (i, bl) in Bootloaders.Select((bldr, idx) => (idx, bldr)))
                {

                    if (i != 0)
                    {
                        if ((i == 1) && bl.Type == Bootloader.BootloaderType.CB)
                        {
                            bl.Encrypt(Bootloaders[i - 1], CPUKey);
                        }
                        else if (bl.Type == Bootloader.BootloaderType.CF)
                            bl.Encrypt(null, CPUKey);
                        else
                        {
                            bl.Encrypt(Bootloaders[i - 1]);
                        }
                    }
                    else
                    {
                        bl.Encrypt();
                    }
                    
                    fs.Write(bl.Data);
                }

                int bytesToPad = (int)(fs.Length % BlockSize.SMALL);
                if (bytesToPad != 0){
                    PrintDebug("Padding ROM to nearest block");
                    fs.Write(new byte[BlockSize.SMALL - bytesToPad]);
                }

                PrintSuccess($"ROM successfully built: {outputPath}");
            }
            catch (Exception ex)
            {
                PrintError($"Error building ROM: {ex.Message}");
            }
        }
    }
}
