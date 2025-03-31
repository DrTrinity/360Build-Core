using System.Text.RegularExpressions;

namespace _360Build_Core.Classes
{
    internal class SMC
    {
        public byte[] Data { get; set; }
        public int Length { get; set; }
        public byte VersionMajor { get; set; }
        public byte VersionMinor { get; set; }
        public byte[] CopyrightInfo => Utils.GetBytes(Data, 0x108, 0x22);

        public bool IsEncrypted { get; set; }


        public SMC(byte[] encData, int offset, int length)
        {
            Data = Utils.GetBytes(encData, offset, length);
            Length = length;

            IsEncrypted = GetEncryptionStatus();
        }

        public static SMC CreateFromFile(string path)
        {
            byte[] smcRaw = File.ReadAllBytes(path);
            SMC smc = new SMC(smcRaw, 0, smcRaw.Length);
            smc.IsEncrypted = false;
            return smc;
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

        public void Encrypt()
        {
            if (IsEncrypted) return;

            int[] Keys = { 0x42, 0x75, 0x4E, 0x79 };
            int i = 0;
            int mod;
            byte[] res = new byte[Length];
            for (i = 0; i < Length; i++)
            {
                mod = (Data[i] ^ (Keys[i & 3] & 0xFF)) * 0xFB;
                res[i] = (byte)(Data[i] ^ (Keys[i & 3] & 0xFF));
                Keys[(i + 1) & 3] += mod;
                Keys[(i + 2) & 3] += (mod >> 8);
            }

            IsEncrypted = true;

            Data = res;
        }

        public void Decrypt()
        {
            if (!IsEncrypted) return;

            int[] Keys = { 0x42, 0x75, 0x4E, 0x79 };
            int i = 0;
            int mod;
            byte[] res = new byte[Length];
            for (i = 0; i < Length; i++)
            {
                mod = (Data[i] * 0xFB);
                res[i] = (byte)(Data[i] ^ (Keys[i & 3] & 0xFF));
                Keys[(i + 1) & 3] += mod;
                Keys[(i + 2) & 3] += (mod >> 8);
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
}