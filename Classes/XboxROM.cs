using System.Buffers.Binary;

namespace _360Build_Core.Classes
{
    public class XboxROM
    {
        public static class BlockSize
        {
            public const int SMALL = 0x1000;
            public const int BIG = 0x20000;
        }

        public class XboxROMHeader
        {
            public int ROMLength { get; set; }

            public ushort Magic { get; set; }
            public ushort Version { get; set; }
            public ushort QFE { get; set; }
            public ushort Flags { get; set; }
            public int _2BLOffset { get; set; }
            public int _6BLOffset { get; set; }
            public byte[]? CopyrightInfo { get; set; }
            public int KVLength { get; set; }
            public int _6BLOffset2 { get; set; }
            public ushort NumOfPatchslots { get; set; }
            public ushort KVVersion { get; set; }
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
                    ms.Write(CopyrightInfo);
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

        public byte[]? CPUKey { get; set; }
        public byte[]? Data { get; set; }

        public ECC _ECC = new ECC();
        public XboxROMHeader Header = new XboxROMHeader();
        public SMC _SMC; //SMC Firmware
        public List<Bootloader> Bootloaders = new List<Bootloader>();

        protected XboxROM() {}
        
        protected XboxROM(string path, string cpukey)
        {
            CPUKey = Utils.StringToByteArray(cpukey); 
            Utils.ValidateCPUKey(CPUKey);
            Data = File.ReadAllBytes(path);
            Load();
        }

        protected XboxROM(string path)
        {
            Data = File.ReadAllBytes(path);
            Load();
        }
        
        public static XboxROM CreateFromFile(string path, string? cpuKey = null)
        {
            var data = File.ReadAllBytes(path);

            if (data.Length == Utils.GetInt(data, 0xC, 4)) 
                return new XboxUpdateROM(path);
        
            return cpuKey != null
                ? new XboxNANDImage(path, cpuKey)
                : new XboxNANDImage(path);
        }

        private void Load()
        {
            //Set Header Variables
            Header.Magic = (ushort)Utils.GetInt(Data, 0, 2);
            Header.Version = (ushort)Utils.GetInt(Data, 0x2, 2);
            Header.QFE = (ushort)Utils.GetInt(Data, 0x4, 2);
            Header.Flags = (ushort)Utils.GetInt(Data, 0x6, 2);
            Header.ROMLength = Data.Length;
            Header._2BLOffset = Utils.GetInt(Data, 0x8, 4);
            Header._6BLOffset = Utils.GetInt(Data, 0xC, 4);
            Header.CopyrightInfo = Utils.GetBytes(Data, 0x10, 0x40);
            Header.KVLength = Utils.GetInt(Data, 0x60, 4);
            Header._6BLOffset2 = Utils.GetInt(Data, 0x64, 4);
            Header.NumOfPatchslots = (ushort)Utils.GetInt(Data, 0x68, 2);
            Header.KVVersion = (ushort)Utils.GetInt(Data, 0x6A, 2);
            Header.KVOffset = Utils.GetInt(Data, 0x6C, 4);
            Header.PatchslotSize = Utils.GetInt(Data, 0x70, 4);
            Header.SMCConfigOffset = Utils.GetInt(Data, 0x74, 4);
            Header.SMCOffset = Utils.GetInt(Data, 0x7C, 4);
            Header.SMCLength = Utils.GetInt(Data, 0x78, 4);

            Logger.LogInfo($"Loading XboxROM. Version: {Header.Version}");
            
            Logger.LogDebug($"Header Information:");
            Logger.LogDebug(
                $"Magic: {Utils.ByteArrayToString(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(Header.Magic)))}");
            Logger.LogDebug($"Build Version: 2.0.{Header.Version}");
            Logger.LogDebug($"QFE: {Header.QFE}");
            Logger.LogDebug($"Flags: {Header.Flags}");
            Logger.LogDebug($"2BL Offset: 0x{Header._2BLOffset:X}");
            Logger.LogDebug($"6BL Offset: 0x{Header._6BLOffset:X}");
            Logger.LogDebug($"Patchslot Count: {Header.NumOfPatchslots}");
            Logger.LogDebug($"Patchslot Size: 0x{Header.PatchslotSize:X}");
            Logger.LogDebug($"KV Version: 0x{Header.KVVersion:X}");
            Logger.LogDebug($"KV Offset: 0x{Header.KVOffset:X}");
            Logger.LogDebug($"KV Length: 0x{Header.KVLength:X}");
            Logger.LogDebug($"SMC Offset: 0x{Header.SMCOffset:X}");
            Logger.LogDebug($"SMC Length: 0x{Header.SMCLength:X}");
            Logger.LogDebug($"SMC Config Offset: 0x{Header.SMCConfigOffset:X}");

            if (Header.QFE != 0)
            {
                Logger.LogDebug($"QFE populated. ROM seems to be non-retail");
            }
            
            //Strip ECC
            if (ECC.GetSpareDataType(Data) != ECC.SpareDataType.NONE)
            {
                Logger.LogDebug("ECC spare data found. Stripping...");
                Logger.LogDebug($"Spare data type is {ECC.GetSpareDataType(Data)}.");
                
                _ECC.LoadSpareData(Data);
                
                Data = ECC.UnEcc(Data);
            }

            //SMC Load and Decryption
            _SMC = new SMC(Data, Header.SMCOffset, Header.SMCLength);
            _SMC.Decrypt();
            Logger.LogDebug($"SMC Firmware Found: Version: {_SMC.VersionMajor}.{_SMC.VersionMinor:D2}. Decrypting...");

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

            foreach (var (i, bl) in Bootloaders.Select((bldr, idx) => (idx, bldr)))
            {
                Logger.LogDebug($"Bootloader found: {bl.Type} {bl.Version}. Decrypting...");

                if (i != 0)
                {
                    if ((i == 1) && bl.Type == Bootloader.BootloaderType.CB)
                    {
                        bl.Decrypt(Bootloaders[i - 1], CPUKey);
                    }
                    // else if (bl.Type == Bootloader.BootloaderType.CF)
                    //     bl.Decrypt(null, CPUKey);
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

    public class XboxUpdateROM : XboxROM
    {
        public XboxUpdateROM()
        {
        }

        public XboxUpdateROM(string path) : base(path)
        {
        }

        public void Build(string outputPath)
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
                    {
                        bl.Encrypt(null, CPUKey);
                    }
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
            if (bytesToPad != 0)
            {
                fs.Write(new byte[BlockSize.SMALL - bytesToPad]);
            }
        }
    }

    public class XboxNANDImage : XboxROM
    {
        public XboxNANDImage()
        {
        }

        public XboxNANDImage(string path, string cpukey) : base(path, cpukey)
        {
            
        }
        
        public XboxNANDImage(string path) : base(path)
        {
            
        }

        public void Build(string outputPath)
        {
            Logger.LogInfo("Building Xbox NAND Image...");
        }
    }
}