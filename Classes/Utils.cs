using System.Collections;
using System.Security.Cryptography;
using _360Build_Core.Exceptions;

namespace _360Build_Core.Classes
{
    public static class Utils
    {
        public static byte[] GetBytes(byte[] data, int offset, int length)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (offset < 0 || offset + length > data.Length)
                throw new InvalidDataException($"Requested {length} bytes at offset {offset}, but data is only {data.Length} bytes long.");
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
            if (!hex.All("0123456789abcdefABCDEF".Contains)) throw new InvalidDataException("String is not a valid hex string");
            
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

        public static bool GetBit(this byte src, int bitNumber)
        {
            return (src & (1 << bitNumber)) != 0;
        }

        public static void ValidateCPUKey(byte[] key)
        {
            if (!IsCPUKeyValid(key)) throw new InvalidCPUKeyException();
        }

        public static bool IsCPUKeyValid(byte[] key, bool fixKey = false)
        {
            if (key.Length != 0x10) return false;
            
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
            if (key[13].GetBit(0))
            {    //shift 0, get t/f
                hamming++;
            }

            if (key[13].GetBit(1)) //shift to left one, get t/f. add 
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