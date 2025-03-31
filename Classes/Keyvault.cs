namespace _360Build_Core.Classes;

internal class Keyvault
{
    public byte[] Data
    {
        get
        {
            if (IsEncrypted) return Utils.ConcatByteArrays(Salt, _EncodedData);

            return Utils.ConcatByteArrays(Key, _DecodedData);
        }
    }

    public int Length { get; set; }
    public byte[] Salt { get; set; }
    public byte[] Key { get; set; }

    protected byte[] _EncodedData { get; set; }
    protected byte[] _DecodedData { get; set; }
    public bool IsEncrypted { get; set; }

    public Keyvault(byte[] encData, int offset, int length)
    {
        Length = length;
        Salt = Utils.GetBytes(encData, offset, 0x10);

        IsEncrypted = true;

        if (IsEncrypted)
            _EncodedData = Utils.GetBytes(encData, offset + 0x10, Length - 0x10);
        else
            _DecodedData = Utils.GetBytes(encData, offset + 0x10, Length - 0x10);
    }

    public static Keyvault CreateFromFile(string path)
    {
        byte[] kv_raw = File.ReadAllBytes(path);
        Keyvault kv = new Keyvault(kv_raw, 0, kv_raw.Length);
        kv.IsEncrypted = false;
        return kv;
    }

    public void Dump(string path)
    {
        try
        {
            File.WriteAllBytes(path, Data);
        }
        catch (Exception ex)
        {
            //PrintError($"Error dumping SMC to {path}: {ex.Message}");
            throw;
        }
    }

    public void Encrypt(byte[] cpuKey)
    {
        if (IsEncrypted) return;

        Salt = Utils.GenerateSalt();

        Key = Utils.GetHMACKey(cpuKey, Salt);

        _EncodedData = RC4.Apply(_DecodedData, Key);

        IsEncrypted = true;
    }

    public void Decrypt(byte[] cpuKey)
    {
        if (!IsEncrypted) return;

        Key = Utils.GetHMACKey(cpuKey, Salt);

        _DecodedData = RC4.Apply(_EncodedData, Key);

        IsEncrypted = false;
    }
}