using System.Collections;
using System.Security.Cryptography;

namespace _360Build_Core.Classes
{
    internal static class Utils
    {
        public enum BLOCK_TYPE
        {
            NONE,
            SMALL,
            BIG_ON_SMALL,
            BIG
        };

        internal static uint CalcEcc(byte[] data)
        {
            uint val = 0, v = 0;
            for (uint bit = 0; bit < 0x1066; bit++)
            {
                if ((bit & 31) == 0)
                    v = ~BitConverter.ToUInt32(data, (int)(bit / 8));
                val ^= v & 1;
                v >>= 1;
                if ((val & 1) != 0)
                    val ^= 0x6954559;
                val >>= 1;
            }

            val = ~val;
            return (val << 6) & 0xFFFFFFFF;
        }

        internal static byte[] AddEcc(byte[] data, BLOCK_TYPE blockType = BLOCK_TYPE.BIG_ON_SMALL)
        {
            using (var rms = new MemoryStream(data))
            using (var wms = new MemoryStream())
            {
                int block = 0;
                while (rms.Position < data.Length)
                {
                    byte[] buff = new byte[528];
                    rms.Read(buff, 0, 512);

                    using (var ms = new MemoryStream(buff))
                    using (var bw = new BinaryWriter(ms))
                    {
                        ms.Seek(512, SeekOrigin.Begin);
                        if (blockType == BLOCK_TYPE.BIG_ON_SMALL)
                        {
                            bw.Write((byte)0);
                            bw.Write((uint)(block / 32));
                            bw.Write(new byte[] { 0xFF, 0, 0 });
                        }
                        else if (blockType == BLOCK_TYPE.BIG)
                        {
                            bw.Write((byte)0xFF);
                            bw.Write((uint)(block / 256));
                            bw.Write(new byte[] { 0, 0, 0 });
                        }
                        else if (blockType == BLOCK_TYPE.SMALL)
                        {
                            bw.Write((uint)(block / 32));
                            bw.Write(new byte[] { 0, 0xFF, 0, 0 });
                        }
                        else
                            return null;

                        buff = ms.ToArray();
                    }

                    Buffer.BlockCopy(BitConverter.GetBytes(CalcEcc(buff)), 0, buff, 524, 4);
                    block++;
                    wms.Write(buff, 0, buff.Length);
                }

                return wms.ToArray();
            }
        }

        internal static byte[] UnEcc(byte[] data)
        {
            using (var rms = new MemoryStream(data))
            using (var wms = new MemoryStream())
            {
                for (int i = 0; i < data.Length / 528; i++)
                {
                    byte[] buff = new byte[512];
                    rms.Read(buff, 0, buff.Length);
                    rms.Seek(0x10, SeekOrigin.Current);
                    wms.Write(buff, 0, buff.Length);
                }

                return wms.ToArray();
            }
        }

        public static byte[] GetBytes(byte[] data, int offset, int length)
        {
            if (data == null) return null;
            if (length < 0) length = 0;
            byte[] templist = new byte[length];

            if (offset + length > data.Length)
            {
                length = data.Length - offset;
            }

            if (length <= data.Length && length >= 0)
            {
                Buffer.BlockCopy(data, offset, templist, 0x00, length);
            }

            return templist;
        }

        public static int GetInt(byte[] data, int offset, int length)
        {
            byte[] bytes = GetBytes(data, offset, length);
            return Convert.ToInt32(ByteArrayToString(bytes), 16);
        }

        public static int ByteArrayToInt(byte[] value)
        {
            return Convert.ToInt32(ByteArrayToString(value), 16);
        }

        public static int ByteArrayToIntBE(byte[] value)
        {
            Array.Reverse(value);
            return Convert.ToInt32(ByteArrayToString(value), 16);
        }

        public static string ByteArrayToString(byte[] ba, int startindex = 0, int length = 0)
        {
            if (ba == null) return "";
            string hex = BitConverter.ToString(ba);
            if (startindex == 0 && length == 0) hex = BitConverter.ToString(ba);
            else if (length == 0 && startindex != 0) hex = BitConverter.ToString(ba, startindex);
            else hex = BitConverter.ToString(ba, startindex, length);
            return hex.Replace("-", "");
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            if (NumberChars % 2 != 0)
            {
                hex = "0" + hex;
                NumberChars++;
            }

            if (NumberChars % 4 != 0)
            {
                hex = "00" + hex;
                NumberChars += 2;
            }

            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static byte[] ConcatByteArrays(params byte[][] arrays)
        {
            return arrays.SelectMany(x => x).ToArray();
        }
        
        public static bool ByteArrayCompare(byte[] a1, byte[] a2, int size = 0)
        {
            if (a1 == null || a2 == null) return false;
            if (size == 0)
            {
                size = a1.Length;
                if (a1.Length != a2.Length)
                    return false;
            }

            for (int i = 0; i < size; i++)
                if (a1[i] != a2[i])
                    return false;

            return true;
        }

        public static byte[] GetHMACKey(byte[] key, byte[] salt)
        {
            byte[] hash = new HMACSHA1(key).ComputeHash(salt);
            return Utils.GetBytes(hash, 0, 0x10);
        }

        public static byte[] GenerateSalt()
        {
            Random r = new Random();
            byte[] _salt = new byte[0x10];
            r.NextBytes(_salt);
            return _salt;
        }

        public static bool getBit(this byte src, int bitNumber)
        {
            return (src & (1 << bitNumber)) != 0;
        }
        
        public static bool IsCPUKeyValid(byte[] key, bool fixKey = false)
        {
            byte[] generatedKey;
            byte[] hammingArray = new byte[13];
            int hamming = 0;

            //CB 74 FC A5 5F 12 64 01 F6 B2 5B 84 2D 
            //A6 C2 97 cut 

            // C    B    7    4
            //1100 1011 0111 0100
            Buffer.BlockCopy(key, 0, hammingArray, 0, 13);
            BitArray bitArray = new BitArray(hammingArray); //array of true/false for 0/1 ez


            foreach (bool s in bitArray)
            {
                if (s) hamming++; //if true, increase hamming
            }
            //if hamming is 53 already, great. make sure both checks below fail.

            //Don't pull your hair out like I did for a bit, 13 is A6 in the cut off portion. I forgot about 0 hehe
            //1010 0110 in binary 
            if (key[13].getBit(0))
            {    //shift 0, get t/f
                hamming++;
            }

            if (key[13].getBit(1)) //shift to left one, get t/f. add 
            {
                hamming++;
            }


            if (hamming != 53)
            {
                hamming = 0;
                return false;
            }

            generatedKey = CalculateCPUKeyECD(key);

            if (fixKey) Array.Copy(generatedKey, key, 16);

            if (!Utils.ByteArrayCompare(key, generatedKey)) return false;
            else return true;
        }
        
        public static byte[] CalculateCPUKeyECD(byte[] key)
        {
            byte[] ecd = new byte[0x10];
            Buffer.BlockCopy(key, 0, ecd, 0, 0x10); //src, offsetstart, dst, offsetstart, len

            uint acc1 = 0, acc2 = 0;

            for (var cnt = 0; cnt < 0x80; cnt++, acc1 >>= 1)
            {

                var bTmp = ecd[cnt >> 3];
                var dwTmp = (uint)((bTmp >> (cnt & 7)) & 1);
                if (cnt < 0x6A)
                {
                    acc1 = dwTmp ^ acc1;
                    if ((acc1 & 1) > 0)
                        acc1 = acc1 ^ 0x360325;
                    acc2 = dwTmp ^ acc2;
                }
                else if (cnt < 0x7F)
                {
                    if (dwTmp != (acc1 & 1))
                        ecd[(cnt >> 3)] = (byte)((1 << (cnt & 7)) ^ (bTmp & 0xFF));
                    acc2 = (acc1 & 1) ^ acc2;
                }
                else if (dwTmp != acc2)
                    ecd[0xF] = (byte)((0x80 ^ bTmp) & 0xFF);
            }

            return ecd;
        }
    }
}