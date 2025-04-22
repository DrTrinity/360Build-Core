using System.Text.RegularExpressions;

namespace _360Build_Core.Classes;

public class Smc
{
    public Smc(byte[]? encData, int offset, int length)
    {
        Data = Utils.GetBytes(encData, offset, length);
        Length = length;

        IsEncrypted = GetEncryptionStatus();
    }

    public byte[]? Data { get; set; }
    public int Length { get; set; }
    public byte VersionMajor { get; set; }
    public byte VersionMinor { get; set; }
    public byte[]? CopyrightInfo => Utils.GetBytes(Data, 0x108, 0x22);
    public bool IsEncrypted { get; set; }

    public static Smc CreateFromFile(string path)
    {
        var smcRaw = File.ReadAllBytes(path);
        var smc = new Smc(smcRaw, 0, smcRaw.Length);
        return smc;
    }

    public void Dump(string path)
    {
        File.WriteAllBytes(path, Data);
    }

    public void Encrypt()
    {
        if (IsEncrypted)
        {
            Logger.LogDebug("SMC is already encrypted. Skipping...");
            return;
        }

        int[] keys = { 0x42, 0x75, 0x4E, 0x79 };
        var i = 0;
        int mod;
        var res = new byte[Length];
        for (i = 0; i < Length; i++)
        {
            mod = (Data[i] ^ (keys[i & 3] & 0xFF)) * 0xFB;
            res[i] = (byte)(Data[i] ^ (keys[i & 3] & 0xFF));
            keys[(i + 1) & 3] += mod;
            keys[(i + 2) & 3] += mod >> 8;
        }

        IsEncrypted = true;

        Data = res;
    }

    public void Decrypt()
    {
        if (!IsEncrypted)
        {
            Logger.LogDebug("SMC is already decrypted. Skipping...");
            return;
        }

        int[] keys = { 0x42, 0x75, 0x4E, 0x79 };
        var i = 0;
        int mod;
        var res = new byte[Length];
        for (i = 0; i < Length; i++)
        {
            mod = Data[i] * 0xFB;
            res[i] = (byte)(Data[i] ^ (keys[i & 3] & 0xFF));
            keys[(i + 1) & 3] += mod;
            keys[(i + 2) & 3] += mod >> 8;
        }

        Data = res;

        IsEncrypted = false;

        VersionMajor = Data[0x101];
        VersionMinor = Data[0x102];
    }

    private bool GetEncryptionStatus()
    {
        return !Regex.IsMatch(Utils.ByteArrayToString(CopyrightInfo), @"^<\s*[a-zA-Z0-9_]+\s*(?:[a-zA-Z0-9_]+\s*)*>$");
    }
}