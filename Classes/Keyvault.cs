namespace _360Build_Core.Classes;

public class Keyvault
{
    public byte[]? Data
    {
        get
        {
            if (IsEncrypted) return Utils.ConcatByteArrays(Salt, EncodedData);

            return Utils.ConcatByteArrays(Key, DecodedData);
        }
    }

    public int Length { get; set; }
    public byte[]? Salt { get; set; }
    public byte[]? Key { get; set; }

    protected byte[]? EncodedData { get; set; }
    protected byte[]? DecodedData { get; set; }
    public bool IsEncrypted { get; set; }

    public Keyvault(byte[]? encData, int offset, int length)
    {
        Length = length;
        Salt = Utils.GetBytes(encData, offset, 0x10);

        IsEncrypted = true;

        if (IsEncrypted)
            EncodedData = Utils.GetBytes(encData, offset + 0x10, Length - 0x10);
        else
            DecodedData = Utils.GetBytes(encData, offset + 0x10, Length - 0x10);
    }

    public static Keyvault CreateFromFile(string path)
    {
        byte[]? kvRaw = File.ReadAllBytes(path);
        Keyvault kv = new Keyvault(kvRaw, 0, kvRaw.Length);
        kv.IsEncrypted = false;
        return kv;
    }

    public void Dump(string path)
    {
        File.WriteAllBytes(path, Data);
    }

    public void Encrypt(byte[]? cpuKey)
    {
        if (IsEncrypted)
        {
            Logger.LogDebug("Keyvault is already encrypted. Skipping...");
            return;
        }
        
        Utils.ValidateCpuKey(cpuKey);

        Salt = Utils.GenerateSalt();

        Key = Utils.GetHmacKey(cpuKey, Salt);

        EncodedData = Rc4.Apply(DecodedData, Key);

        IsEncrypted = true;
    }

    public void Decrypt(byte[]? cpuKey)
    {
        if (!IsEncrypted)
        {
            Logger.LogDebug("Keyvault is already decrypted. Skipping...");
            return;
        }
        
        Utils.ValidateCpuKey(cpuKey);

        Key = Utils.GetHmacKey(cpuKey, Salt);

        DecodedData = Rc4.Apply(EncodedData, Key);

        IsEncrypted = false;
    }
}