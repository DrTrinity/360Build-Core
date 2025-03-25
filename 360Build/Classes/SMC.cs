using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using RC4Cryptography;
using System.Security.Cryptography;

namespace _360Build
{
    internal class SMC
    {
        public byte[] Data { get; set; }
        public int Length { get; set; }
        public byte VersionMajor { get; set; }
        public byte VersionMinor { get; set; }

        public bool IsEncrypted { get; set; }


        public SMC(byte[] encData, int offset, int length)
        {
            Data = Utils.GetBytes(encData, offset, length);
            Length = length;

            IsEncrypted = true;
        }

        public static SMC ReadFromFile(string path)
        {
            byte[] smc_raw = File.ReadAllBytes(path);
            return new SMC(smc_raw, 0, smc_raw.Length);
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

    }
}
