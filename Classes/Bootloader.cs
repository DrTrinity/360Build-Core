using _360Build_Core.Exceptions;

namespace _360Build_Core.Classes;

public abstract class Bootloader
{
    public enum BootloaderType : ushort
    {
        //Retail
        CB = 0x4342,
        CD = 0x4344,
        CE = 0x4345,
        CF = 0x4346,
        CG = 0x4347,

        //Dev/Test
        SB = 0x5342,
        SC = 0x5343,
        SD = 0x5344,
        SE = 0x5345,
        SF = 0x5346,
        SG = 0x5347,

        //WN1
        S2 = 0x5332,
        S3 = 0x5333,
        S4 = 0x5334,
        S5 = 0x5335
    }

    public byte[] Data
    {
        get
        {
            if (IsEncrypted) return Utils.ConcatByteArrays(Header, Salt, _EncodedData);

            return Utils.ConcatByteArrays(Header, Key, _DecodedData);
        }
    }

    public byte[] Header { get; set; }
    public byte[] Key { get; set; }
    public byte[] Salt { get; set; }
    public int EntrypointOffset { get; set; }
    public int Length { get; set; }
    public int Version { get; set; }

    protected byte[] _EncodedData { get; set; }
    protected byte[] _DecodedData { get; set; }
    private int _HeaderLength { get; set; }

    public bool IsEncrypted { get; set; }
    public BootloaderType Type { get; set; }

    public Bootloader(byte[] encData, int offset, bool encrypted = true)
    {
        EntrypointOffset = Utils.GetInt(encData, offset + 0x8, 4);
        Length = Utils.GetInt(encData, offset + 0xC, 4);
        Version = Utils.GetInt(encData, offset + 0x2, 2);
        Header = Utils.GetBytes(encData, offset, 0x10);
        Type = (BootloaderType)Utils.GetInt(encData, offset, 2);
        Salt = Utils.GetBytes(encData, offset + 0x10, 0x10);
        IsEncrypted = encrypted;

        if (IsEncrypted)
            _EncodedData = Utils.GetBytes(encData, offset + Header.Length + 0x10, Length - Header.Length - 0x10);
        else
            _DecodedData = Utils.GetBytes(encData, offset + Header.Length + 0x10, Length - Header.Length - 0x10);

        _HeaderLength = Header.Length;
    }

    public static Bootloader Create(byte[] data, int offset, BootloaderType bootloaderType)
    {
        return bootloaderType switch
        {
            BootloaderType.SB => new SBBootloader(data, offset),
            BootloaderType.SC => new SCBootloader(data, offset),
            BootloaderType.SD => new SDBootloader(data, offset),
            BootloaderType.SE => new SEBootloader(data, offset),
            BootloaderType.CB => new CBBootloader(data, offset),
            BootloaderType.CD => new CDBootloader(data, offset),
            BootloaderType.CE => new CEBootloader(data, offset),
            BootloaderType.CF => new CFBootloader(data, offset),
            BootloaderType.CG => new CGBootloader(data, offset),
            _ => throw new InvalidBootloaderException($"Unknown Bootloader Type {bootloaderType}")
        };
    }

    public static Bootloader CreateFromFile(string path, BootloaderType bootloaderType)
    {
        var data = File.ReadAllBytes(path);

        return bootloaderType switch
        {
            BootloaderType.SB => new SBBootloader(data, 0, false),
            BootloaderType.SC => new SCBootloader(data, 0, false),
            BootloaderType.SD => new SDBootloader(data, 0, false),
            BootloaderType.SE => new SEBootloader(data, 0, false),
            BootloaderType.CB => new CBBootloader(data, 0, false),
            BootloaderType.CD => new CDBootloader(data, 0, false),
            BootloaderType.CE => new CEBootloader(data, 0, false),
            BootloaderType.CF => new CFBootloader(data, 0, false),
            BootloaderType.CG => new CGBootloader(data, 0, false),
            _ => throw new InvalidBootloaderException($"Unknown Bootloader Type {bootloaderType}")
        };
    }

    public void Dump(string path)
    {
        File.WriteAllBytes(path, Data);
    }

    public void Encrypt(Bootloader prevBL = null, byte[] cpuKey = null)
    {
        if (IsEncrypted) return;
        if (cpuKey != null) Utils.ValidateCPUKey(cpuKey);

        var _prevKey = prevBL != null ? prevBL.Key : Globals._1BLKey;
        Salt = Utils.GenerateSalt();
        var _salt = Salt;

        if (prevBL != null && prevBL.Type == BootloaderType.CB && Type == BootloaderType.CB)
        {
            if (cpuKey == null) throw new InvalidCPUKeyException("No CPU key provided to decrypt CB");
            _salt = Utils.ConcatByteArrays(_salt, cpuKey);

            //New CB Encryption Scheme
            if ((Utils.GetInt(Data, 0x6, 2) & 0x1000) != 0)
            {
                var _2BLHeader = prevBL.Header;
                _2BLHeader[0x6] = 0x00;
                _2BLHeader[0x7] = 0x00;
                _salt = Utils.ConcatByteArrays(_salt, _2BLHeader);
            }
        }

        if (Type == BootloaderType.CF) Salt = Utils.ConcatByteArrays(Salt, cpuKey);

        if (Type == BootloaderType.SC)
            Key = Utils.GetHMACKey(new byte[0x10], _salt);
        else
            Key = Utils.GetHMACKey(_prevKey, _salt);
        _EncodedData = RC4.Apply(_DecodedData, Key);

        // if ((prevBL != null) && (prevBL.Type == BootloaderType.CF))
        // {
        //     Key = Utils.GetBytes(Data, 0x330, 0x10);
        // }

        IsEncrypted = true;
    }

    public void Decrypt(Bootloader prevBL = null, byte[] cpuKey = null)
    {
        if (!IsEncrypted) return;
        if (cpuKey != null) Utils.ValidateCPUKey(cpuKey);
            
        var _salt = Salt;
        var _prevKey = prevBL != null ? prevBL.Key : Globals._1BLKey;

        if (prevBL != null && prevBL.Type == BootloaderType.CB && Type == BootloaderType.CB)
        {
            Logger.LogDebug("CB is split");
            if (cpuKey == null) throw new InvalidCPUKeyException("No CPU key provided to decrypt CB");
            
            _salt = Utils.ConcatByteArrays(_salt, cpuKey);

            //New CB Encryption Scheme
            if ((Utils.GetInt(Data, 0x6, 2) & 0x1000) != 0)
            {
                Logger.LogDebug("CB is using v2 encryption scheme");
                var _2BLHeader = prevBL.Header;
                _2BLHeader[0x6] = 0x00;
                _2BLHeader[0x7] = 0x00;
                _salt = Utils.ConcatByteArrays(_salt, _2BLHeader);
            }
        }

        if (prevBL != null && prevBL.Type == BootloaderType.CF)
            Key = Utils.GetBytes(Data, 0x330, 0x10);
        else if (Type == BootloaderType.SC)
            Key = Utils.GetHMACKey(new byte[0x10], _salt);
        else
            Key = Utils.GetHMACKey(_prevKey, _salt);

        _DecodedData = RC4.Apply(_EncodedData, Key);

        IsEncrypted = false;
    }

    // private byte GetSaltOffset(BootloaderType type)
    // {
    //     byte _saltOffset;

    //     switch (type)
    //     {
    //         case BootloaderType.CF:
    //             _saltOffset = 0x20;
    //             break;
    //         default:
    //             _saltOffset = 0x10; // Default salt offset
    //             break;
    //     }

    //     return _saltOffset;

    // }
}

internal class SBBootloader : Bootloader
{
    public byte[] PairingData { get; set; }
    public byte LDV { get; set; }
    public byte ConsoleType { get; set; }
    public byte ConsoleSequence { get; set; }
    public byte[] ConsoleSequenceAllow { get; set; }


    public SBBootloader(byte[] encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }

    public new void Decrypt(Bootloader prevBL = null, byte[] cpuKey = null)
    {
        base.Decrypt(prevBL, cpuKey);

        PairingData = Utils.GetBytes(Data, 0x20, 4);
        LDV = Utils.GetBytes(Data, 0x24, 1)[0];
        ConsoleType = Utils.GetBytes(Data, 0x3B1, 1)[0];
        ConsoleSequence = Utils.GetBytes(Data, 0x3B2, 1)[0];
        ConsoleSequenceAllow = Utils.GetBytes(Data, 0x3B3, 2);
    }
}

internal class SCBootloader : Bootloader
{
    public SCBootloader(byte[] encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class SDBootloader : Bootloader
{
    public SDBootloader(byte[] encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class SEBootloader : Bootloader
{
    public SEBootloader(byte[] encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
        var _bytesToPad = encrypted ? _EncodedData.Length % 0x10 : _DecodedData.Length % 0x10;

        if (_bytesToPad != 0)
        {
            Logger.LogDebug("Padding SE...");
            _EncodedData = Utils.GetBytes(encData, offset + Header.Length + 0x10,
                Length - Header.Length - 0x10 + (0x10 - _bytesToPad));
        }
    }
}

internal class CBBootloader : Bootloader
{
    public CBBootloader(byte[] encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class CDBootloader : Bootloader
{
    public CDBootloader(byte[] encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class CEBootloader : Bootloader
{
    public CEBootloader(byte[] encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class CFBootloader : Bootloader
{
    public CFBootloader(byte[] encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}

internal class CGBootloader : Bootloader
{
    public CGBootloader(byte[] encData, int offset, bool encrypted = true) : base(encData, offset, encrypted)
    {
    }
}