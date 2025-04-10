using System.Buffers.Binary;
using _360Build_Core.Exceptions;

namespace _360Build_Core.Classes;

public class XboxRom
{
    private const int Magic = 0xFF4F;
    public List<Bootloader> Bootloaders = new();

    public Ecc Ecc = new();
    public XboxRomHeader Header = new();
    public List<Patchslot> Patchslots = new();
    public Smc Smc; //SMC Firmware
    public List<Filesystem> Filesystems = new();
    public const int PageSize = 0x200;
    public int BlockSize = (int)BlockType.Small;

    public enum BlockType
    {
        None,
        Small = 0x4000,
        BigOnSmall = 0x4000,
        Big = 0x20000
    }
    
    protected XboxRom()
    {
    }

    protected XboxRom(string path, string cpukey)
    {
        CpuKey = Utils.StringToByteArray(cpukey);
        Utils.ValidateCpuKey(CpuKey);
        Data = File.ReadAllBytes(path);
        Load();
    }

    protected XboxRom(string path)
    {
        Data = File.ReadAllBytes(path);
        Load();
    }

    public byte[]? CpuKey { get; set; }
    public byte[]? Data { get; set; }

    public static XboxRom CreateFromFile(string path, string? cpuKey = null)
    {
        var data = File.ReadAllBytes(path);

        if (data.Length == Utils.GetInt(data, 0xC, 4))
            return new XboxUpdateRom(path);

        return cpuKey != null
            ? new XboxNandImage(path, cpuKey)
            : new XboxNandImage(path);
    }

    private void Load()
    {
        LoadHeader();

        Logger.LogInfo($"Loading XboxROM. Version: {Header.Version}");

        if (Header.Qfe != 0) Logger.LogDebug("QFE populated. ROM seems to be non-retail");

        BlockSize = (int)Ecc.GetSpareDataType(Data);
        
        //Strip ECC
        if (Ecc.GetSpareDataType(Data) != BlockType.None)
        {
            Logger.LogDebug("ECC spare data found. Stripping...");
            Logger.LogDebug($"Spare data type is {Ecc.GetSpareDataType(Data)}.");

            Ecc.LoadSpareData(Data);

            Data = Ecc.UnEcc(Data);
        }

        LoadSmcFirmware();
        LoadBootloaders();
        LoadPatchslots();
        LoadFilesystems();
    }

    private void LoadHeader()
    {
        Logger.LogDebug("Loading header...");
        // Get header magic/set var
        Header.Magic = (ushort)Utils.GetInt(Data, 0, 2);

        // Check if header magic is valid
        if (Header.Magic != Magic) throw new InvalidXboxRomException("Invalid XboxROM magic");
        Logger.LogDebug("Header magic is valid");

        // Set header vars
        Header.Version = (ushort)Utils.GetInt(Data, 0x2, 2);
        Header.Qfe = (ushort)Utils.GetInt(Data, 0x4, 2);
        Header.Flags = (ushort)Utils.GetInt(Data, 0x6, 2);
        Header.RomLength = Data.Length;
        Header._2BLOffset = Utils.GetInt(Data, 0x8, 4);
        Header._6BLOffset = Utils.GetInt(Data, 0xC, 4);
        Header.CopyrightInfo = Utils.GetBytes(Data, 0x10, 0x40);
        Header.KvLength = Utils.GetInt(Data, 0x60, 4);
        Header._6BLOffset2 = Utils.GetInt(Data, 0x64, 4);
        Header.NumOfPatchslots = (ushort)Utils.GetInt(Data, 0x68, 2);
        Header.KvVersion = (ushort)Utils.GetInt(Data, 0x6A, 2);
        Header.KvOffset = Utils.GetInt(Data, 0x6C, 4);
        Header.PatchslotSize = Utils.GetInt(Data, 0x70, 4);
        Header.SmcConfigOffset = Utils.GetInt(Data, 0x74, 4);
        Header.SmcOffset = Utils.GetInt(Data, 0x7C, 4);
        Header.SmcLength = Utils.GetInt(Data, 0x78, 4);

        // Print header info
        Logger.LogDebug("Header Information:");
        Logger.LogDebug(
            $"Magic: {Utils.ByteArrayToString(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(Header.Magic)))}");
        Logger.LogDebug($"Build Version: 2.0.{Header.Version}");
        Logger.LogDebug($"QFE: {Header.Qfe}");
        Logger.LogDebug($"Flags: {Header.Flags}");
        Logger.LogDebug($"2BL Offset: 0x{Header._2BLOffset:X}");
        Logger.LogDebug($"6BL Offset: 0x{Header._6BLOffset:X}");
        Logger.LogDebug($"Patchslot Count: {Header.NumOfPatchslots}");
        Logger.LogDebug($"Patchslot Size: 0x{Header.PatchslotSize:X}");
        Logger.LogDebug($"KV Version: 0x{Header.KvVersion:X}");
        Logger.LogDebug($"KV Offset: 0x{Header.KvOffset:X}");
        Logger.LogDebug($"KV Length: 0x{Header.KvLength:X}");
        Logger.LogDebug($"SMC Offset: 0x{Header.SmcOffset:X}");
        Logger.LogDebug($"SMC Length: 0x{Header.SmcLength:X}");
        Logger.LogDebug($"SMC Config Offset: 0x{Header.SmcConfigOffset:X}");
    }

    private void LoadSmcFirmware()
    {
        //SMC Load and Decryption
        Logger.LogDebug("Loading SMC firmware...");
        Smc = new Smc(Data, Header.SmcOffset, Header.SmcLength);
        Smc.Decrypt();
        Logger.LogDebug($"SMC Firmware Found: Version: {Smc.VersionMajor}.{Smc.VersionMinor:D2}. Decrypting...");
    }

    private void LoadBootloaders()
    {
        Logger.LogDebug("Loading bootloaders...");
        Bootloaders = new List<Bootloader>();

        var offset = Header._2BLOffset;
        while (Enum.IsDefined(typeof(Bootloader.BootloaderType), (ushort)Utils.GetInt(Data, offset, 2)))
        {
            var blType = (Bootloader.BootloaderType)Utils.GetInt(Data, offset, 2);
            var bl = Bootloader.Create(Data, offset, blType);
            Bootloaders.Add(bl);
            offset += bl.Length;
        }

        try
        {
            foreach (var (i, bl) in Bootloaders.Select((bldr, idx) => (idx, bldr)))
            {
                Logger.LogDebug($"Bootloader found: {bl.Type} {bl.Version}. Decrypting...");

                if (i != 0)
                {
                    if (i == 1 && bl.Type == Bootloader.BootloaderType.CB)
                        bl.Decrypt(Bootloaders[i - 1], CpuKey);
                    // else if (bl.Type == Bootloader.BootloaderType.CF)
                    //     bl.Decrypt(null, CPUKey);
                    else
                        bl.Decrypt(Bootloaders[i - 1]);
                }
                else
                {
                    bl.Decrypt();
                }
            }
        }
        catch (Exception e)
        {
            Logger.LogWarning("Failed to decrypt bls, skipping...");
        }
    }

    private void LoadPatchslots()
    {
        Patchslots = new List<Patchslot>();

        if (Header.RomLength == Data.Length)
        {
            Logger.LogDebug("Image is too small for patchslots. Skipping...");
            return;
        }
        
        if (Header.NumOfPatchslots < 1)
        {
            Logger.LogDebug("Patchslot count is zero, skipping...");
            return;
        }

        Logger.LogDebug("Loading patchslots...");

        for (var i = 0; i < Header.NumOfPatchslots; i++)
            try
            {
                var ps = new Patchslot(Data, i * Header.PatchslotSize + Header._6BLOffset,
                    Header.PatchslotSize);

                Logger.LogDebug(
                    $"Patchslot found: {ps.CfSf.Type} {ps.CfSf.Version} - {ps.CgSg.Type} {ps.CgSg.Version}");
                Patchslots.Add(ps);
            }
            catch (InvalidPatchslotException ex)
            {
                Logger.LogDebug("Invalid patchslot found. Skipping...");
            }

        for (var i = 0; i < Patchslots.Count; i++)
            foreach (var (j, bl) in Patchslots[i].Select((bldr, idx) => (idx, bldr)))
                if (j != 0)
                    bl.Decrypt(Patchslots[i].First());
                else
                    bl.Decrypt();
    }

    private void LoadFilesystems()
    {
        if (Header.RomLength == Data.Length)
        {
            Logger.LogDebug("Image is too small for filesystem. Skipping...");
            return;
        }
        
        int fsCount = 0;
                
        foreach (Ecc.SpareData spare in Ecc.SpareDatas)
        {
            fsCount++;
            if (spare.FsBlockType == Ecc.SpareData.SpareDataBlockType.FsRootEntry)
            {
                if (Filesystems.Any(fs => fs.Version == spare.FsSequence)) continue;
                int fsOffset = (PageSize * fsCount) - PageSize;
                Filesystems.Add(new Filesystem(Utils.GetBytes(Data, fsOffset, 0x4000), 0, spare.FsSequence, this));
                        
                Logger.LogDebug($"Filesystem found at 0x{fsOffset:X}. Version {spare.FsSequence}");
            }
        }
        
        Filesystem current = Filesystems.OrderByDescending(fs => fs.Version).FirstOrDefault();
        if (current != null)
        {
            current.IsCurrent = true;
        }
    }
    
    public class XboxRomHeader
    {
        public int RomLength { get; set; }

        public ushort Magic { get; set; }
        public ushort Version { get; set; }
        public ushort Qfe { get; set; }
        public ushort Flags { get; set; }
        public int _2BLOffset { get; set; }
        public int _6BLOffset { get; set; }
        public byte[]? CopyrightInfo { get; set; }
        public int KvLength { get; set; }
        public int _6BLOffset2 { get; set; }
        public ushort NumOfPatchslots { get; set; }
        public ushort KvVersion { get; set; }
        public int KvOffset { get; set; }
        public int PatchslotSize { get; set; }
        public int SmcConfigOffset { get; set; }
        public int SmcLength { get; set; }
        public int SmcOffset { get; set; }

        public byte[] Data
        {
            get
            {
                using MemoryStream ms = new();

                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(Magic)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(Version)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(Qfe)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(Flags)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(_2BLOffset)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(_6BLOffset)));
                ms.Write(CopyrightInfo);
                ms.Write(new byte[0x10]);
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(KvLength)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(_6BLOffset2)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(NumOfPatchslots)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(KvVersion)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(KvOffset)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(PatchslotSize)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(SmcConfigOffset)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(SmcLength)));
                ms.Write(BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(SmcOffset)));

                return ms.ToArray();
            }
        }
    }
}

public class XboxUpdateRom : XboxRom
{
    public XboxUpdateRom()
    {
    }

    public XboxUpdateRom(string path) : base(path)
    {
    }

    public void Build(string outputPath)
    {
        using FileStream fs = new(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);

        fs.Write(Header.Data);
        fs.Write(new byte[Header.SmcOffset - fs.Length]);

        Smc.Encrypt();
        fs.Write(Smc.Data);

        fs.Write(new byte[Header._2BLOffset - fs.Length]);

        foreach (var (i, bl) in Bootloaders.Select((bldr, idx) => (idx, bldr)))
        {
            if (i != 0)
            {
                if (i == 1 && bl.Type == Bootloader.BootloaderType.CB)
                    bl.Encrypt(Bootloaders[i - 1], CpuKey);
                else if (bl.Type == Bootloader.BootloaderType.CF)
                    bl.Encrypt(null, CpuKey);
                else
                    bl.Encrypt(Bootloaders[i - 1]);
            }
            else
            {
                bl.Encrypt();
            }

            fs.Write(bl.Data);
        }

        var bytesToPad = (int)(fs.Length % BlockSize);
        if (bytesToPad != 0) fs.Write(new byte[BlockSize - bytesToPad]);
    }
}

public class XboxNandImage : XboxRom
{
    public XboxNandImage()
    {
    }

    public XboxNandImage(string path, string cpukey) : base(path, cpukey)
    {
    }

    public XboxNandImage(string path) : base(path)
    {
    }

    public void Build(string outputPath)
    {
        Logger.LogInfo("Building Xbox NAND Image...");
    }
}