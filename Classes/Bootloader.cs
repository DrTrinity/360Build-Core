using _360Build_Core.Exceptions;

namespace _360Build_Core.Classes;

public abstract class Bootloader
{
    public enum BootloaderType : ushort
    {
        // Retail
        CB = 0x4342,
        CD = 0x4344,
        CE = 0x4345,
        CF = 0x4346,
        CG = 0x4347,

        // Dev/Test
        SB = 0x5342,
        SC = 0x5343,
        SD = 0x5344,
        SE = 0x5345,
        SF = 0x5346,
        SG = 0x5347,

        // WN1
        S2 = 0x5332,
        S3 = 0x5333,
        S4 = 0x5334,
        S5 = 0x5335
    }

    public byte[]? Data
    {
        get
        {
            if (IsEncrypted) return Utils.ConcatByteArrays(Header, Salt, EncodedData);

            return Utils.ConcatByteArrays(Header, Key, DecodedData);
        }
    }

    public byte[]? Header { get; set; }
    public byte[]? Key { get; set; }
    public byte[]? Salt { get; set; }
    public int EntrypointOffset { get; set; }
    public int Length { get; set; }
    public int Version { get; set; }

    protected byte[]? EncodedData { get; set; }
    protected byte[]? DecodedData { get; set; }

    public bool IsEncrypted { get; set; }
    public BootloaderType Type { get; set; }

    public Bootloader(byte[]? encData, int offset, bool encrypted = true)
    {
        // Load header info
        EntrypointOffset = Utils.GetInt(encData, offset + 0x8, 4);
        Length = Utils.GetInt(encData, offset + 0xC, 4);
        Version = Utils.GetInt(encData, offset + 0x2, 2);
        Header = Utils.GetBytes(encData, offset, 0x10);
        Type = (BootloaderType)Utils.GetInt(encData, offset, 2);
        Salt = Utils.GetBytes(encData, offset + 0x10, 0x10);
        IsEncrypted = encrypted;

        if (IsEncrypted)
            EncodedData = Utils.GetBytes(encData, offset + Header.Length + 0x10, Length - Header.Length - 0x10);
        else
            DecodedData = Utils.GetBytes(encData, offset + Header.Length + 0x10, Length - Header.Length - 0x10);
    }

    public static Bootloader Create(byte[]? data, int offset, BootloaderType bootloaderType)
    {
        return bootloaderType switch
        {
            BootloaderType.SB => new SbBootloader(data, offset),
            BootloaderType.SC => new ScBootloader(data, offset),
            BootloaderType.SD => new SdBootloader(data, offset),
            BootloaderType.SE => new SeBootloader(data, offset),
            BootloaderType.CB => new CbBootloader(data, offset),
            BootloaderType.CD => new CdBootloader(data, offset),
            BootloaderType.CE => new CeBootloader(data, offset),
            BootloaderType.CF => new CfBootloader(data, offset),
            BootloaderType.CG => new CgBootloader(data, offset),
            _ => throw new InvalidBootloaderException($"Unknown Bootloader Type {bootloaderType}")
        };
    }

    public static Bootloader CreateFromFile(string path, BootloaderType bootloaderType)
    {
        var data = File.ReadAllBytes(path);

        return bootloaderType switch
        {
            BootloaderType.SB => new SbBootloader(data, 0, false),
            BootloaderType.SC => new ScBootloader(data, 0, false),
            BootloaderType.SD => new SdBootloader(data, 0, false),
            BootloaderType.SE => new SeBootloader(data, 0, false),
            BootloaderType.CB => new CbBootloader(data, 0, false),
            BootloaderType.CD => new CdBootloader(data, 0, false),
            BootloaderType.CE => new CeBootloader(data, 0, false),
            BootloaderType.CF => new CfBootloader(data, 0, false),
            BootloaderType.CG => new CgBootloader(data, 0, false),
            _ => throw new InvalidBootloaderException($"Unknown Bootloader Type {bootloaderType}")
        };
    }

    public void Dump(string path)
    {
        File.WriteAllBytes(path, Data);
    }

    public void Encrypt(Bootloader? prevBl = null, byte[]? cpuKey = null)
    {
        if (IsEncrypted)
        {
            Logger.LogDebug($"{Type} bootloader is already encrypted. Skipping...");
            return;
        }
        
        if (cpuKey != null) Utils.ValidateCpuKey(cpuKey);

        var prevKey = prevBl != null ? prevBl.Key : Globals._1BLKey;
        Salt = Utils.GenerateSalt();
        var salt = Salt;

        if (prevBl != null && prevBl.Type == BootloaderType.CB && Type == BootloaderType.CB)
        {
            if (cpuKey == null) throw new InvalidCpuKeyException("No CPU key provided to decrypt CB");
            salt = Utils.ConcatByteArrays(salt, cpuKey);

            //New CB Encryption Scheme
            if ((Utils.GetInt(Data, 0x6, 2) & 0x1000) != 0)
            {
                var _2BLHeader = prevBl.Header;
                _2BLHeader[0x6] = 0x00;
                _2BLHeader[0x7] = 0x00;
                salt = Utils.ConcatByteArrays(salt, _2BLHeader);
            }
        }
        
        if (prevBl != null && prevBl.Type == BootloaderType.CF && Type == BootloaderType.CG)
            Key = Utils.GetHmacKey(Utils.GetBytes(prevBl.Data, 0x330, 0x10), salt);
        if (Type == BootloaderType.SC)
            Key = Utils.GetHmacKey(new byte[0x10], salt);
        else
            Key = Utils.GetHmacKey(prevKey, salt);
        
        EncodedData = Rc4.Apply(DecodedData, Key);

        IsEncrypted = true;
    }

    public void Decrypt(Bootloader? prevBl = null, byte[]? cpuKey = null)
    {
        if (!IsEncrypted)
        {
            Logger.LogDebug($"{Type} bootloader is already decrypted. Skipping...");
            return;
        }
        
        if (cpuKey != null) Utils.ValidateCpuKey(cpuKey);
            
        var salt = Salt;
        var prevKey = prevBl != null ? prevBl.Key : Globals._1BLKey;

        if (prevBl != null && prevBl.Type == BootloaderType.CB && Type == BootloaderType.CB)
        {
            Logger.LogDebug("CB is split");
            if (cpuKey == null) throw new InvalidCpuKeyException("No CPU key provided to decrypt CB_B");
            
            salt = Utils.ConcatByteArrays(salt, cpuKey);

            //New CB Encryption Scheme
            if ((Utils.GetInt(Data, 0x6, 2) & 0x1000) != 0)
            {
                Logger.LogDebug("CB is using v2 encryption scheme");
                var _2BLHeader = prevBl.Header;
                _2BLHeader[0x6] = 0x00;
                _2BLHeader[0x7] = 0x00;
                salt = Utils.ConcatByteArrays(salt, _2BLHeader);
            }
        }

        if (prevBl != null && prevBl.Type == BootloaderType.CF && Type == BootloaderType.CG)
            Key = Utils.GetHmacKey(Utils.GetBytes(prevBl.Data, 0x330, 0x10), salt);
        else if (Type == BootloaderType.SC)
            Key = Utils.GetHmacKey(new byte[0x10], salt);
        else
            Key = Utils.GetHmacKey(prevKey, salt);
        
        DecodedData = Rc4.Apply(EncodedData, Key);

        IsEncrypted = false;
    }
}

internal class SbBootloader : Bootloader
{
    public byte[]? PairingData { get; set; }
    public byte Ldv { get; set; }
    public byte ConsoleType { get; set; }
    public byte ConsoleSequence { get; set; }
    public byte[]? ConsoleSequenceAllow { get; set; }


    public SbBootloader(byte[]? encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }

    public new void Decrypt(Bootloader prevBl = null, byte[]? cpuKey = null)
    {
        base.Decrypt(prevBl, cpuKey);

        PairingData = Utils.GetBytes(Data, 0x20, 4);
        Ldv = Utils.GetBytes(Data, 0x24, 1)[0];
        ConsoleType = Utils.GetBytes(Data, 0x3B1, 1)[0];
        ConsoleSequence = Utils.GetBytes(Data, 0x3B2, 1)[0];
        ConsoleSequenceAllow = Utils.GetBytes(Data, 0x3B3, 2);
    }
}

internal class ScBootloader : Bootloader
{
    public ScBootloader(byte[]? encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class SdBootloader : Bootloader
{
    public SdBootloader(byte[]? encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class SeBootloader : Bootloader
{
    public SeBootloader(byte[]? encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
        var bytesToPad = encrypted ? EncodedData.Length % 0x10 : DecodedData.Length % 0x10;

        if (bytesToPad != 0)
        {
            Logger.LogDebug("Padding SE...");
            EncodedData = Utils.GetBytes(encData, offset + Header.Length + 0x10,
                Length - Header.Length - 0x10 + (0x10 - bytesToPad));
        }
    }
}

internal class CbBootloader : Bootloader
{
    public CbBootloader(byte[]? encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class CdBootloader : Bootloader
{
    public CdBootloader(byte[]? encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class CeBootloader : Bootloader
{
    public CeBootloader(byte[]? encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class CfBootloader : Bootloader
{
    public CfBootloader(byte[]? encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
        Header = Utils.GetBytes(encData, offset, 0x20);
        Salt = Utils.GetBytes(encData, offset + 0x20, 0x10);
        
        if (IsEncrypted)
            EncodedData = Utils.GetBytes(encData, offset + Header.Length + 0x10, Length - Header.Length - 0x10);
        else
            DecodedData = Utils.GetBytes(encData, offset + Header.Length + 0x10, Length - Header.Length - 0x10);
    }
}

internal class CgBootloader : Bootloader
{
    public CgBootloader(byte[]? encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}