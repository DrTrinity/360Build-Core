using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace _360Build
{
    internal class Utils
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

        public static byte[] ReturnPortion(byte[] data, int offset, int length)
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
            byte[] bytes = ReturnPortion(data, offset, length);
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

        public static byte[] GetHMACKey(byte[] key, byte[] salt)
        {
            byte[] hash = new HMACSHA1(key).ComputeHash(salt);
            return Utils.ReturnPortion(hash, 0, 0x10);
        }
    }
}
