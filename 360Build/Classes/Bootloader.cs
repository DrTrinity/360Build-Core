using RC4Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static _360Build.ConsoleLogger;

namespace _360Build
{
    internal class Bootloader
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
            S5 = 0x5335,

        }

        public byte[] Data
        {
            get
            {
                if (IsEncrypted)
                {
                    return Utils.ConcatByteArrays(Header, Salt, _EncodedData);
                }
                else
                {
                    return Utils.ConcatByteArrays(Header, Key, _DecodedData);
                }
            }
        }

        public byte[] Header { get; set; }
        public byte[] Key { get; set; }
        public byte[] Salt { get; set; }
        public int EntrypointOffset { get; set; }
        public int Length { get; set; }
        public int Version { get; set; }
        public int LDV { get; set; }

        private byte[] _EncodedData { get; set; }
        private byte[] _DecodedData { get; set; }
        private int _HeaderLength { get; set; }

        public bool IsEncrypted { get; set; }
        public BootloaderType Type { get; set; }

        public Bootloader(byte[] encData, int offset, int headerLength = 0x10)
        {
            EntrypointOffset = Utils.GetInt(encData, offset + 0x8, 4);
            Length = Utils.GetInt(encData, offset + 0xC, 4);
            Version = Utils.GetInt(encData, offset + 0x2, 2);
            Header = Utils.GetBytes(encData, offset, headerLength);
            Type = (BootloaderType)Utils.GetInt(encData, offset, 2);
            Salt = Utils.GetBytes(encData, offset + GetSaltOffset(Type), 0x10);

            IsEncrypted = true;

            _EncodedData = Utils.GetBytes(encData, offset + headerLength + 0x10, Length - headerLength - 0x10);
            _HeaderLength = headerLength;
        }

        public static Bootloader ReadFromFile(string path)
        {
            return new Bootloader(File.ReadAllBytes(path), 0);
        }

        public void Encrypt(Bootloader prevBL = null, byte[] cpuKey = null)
        {
            if (IsEncrypted) return;

            byte[] _prevKey = (prevBL != null) ? prevBL.Key : Globals._1BLKey;
            Salt = Utils.GenerateSalt();
            byte[] _salt = Salt;

            if ((prevBL != null) && (prevBL.Type == BootloaderType.CB) && (Type == BootloaderType.CB))
            {
                _salt = Utils.ConcatByteArrays(_salt, cpuKey);

                //New CB Encryption Scheme
                if ((Utils.GetInt(Data, 0x6, 2) & 0x1000) != 0)
                {
                    byte[] _2BLHeader = prevBL.Header;
                    _2BLHeader[0x6] = 0x00;
                    _2BLHeader[0x7] = 0x00;
                    _salt = Utils.ConcatByteArrays(_salt, _2BLHeader);
                }
            }

            if (Type == BootloaderType.CF)
            {
                Salt = Utils.ConcatByteArrays(Salt, cpuKey);
            }

            Key = Utils.GetHMACKey(_prevKey, _salt);
            _EncodedData = RC4.Apply(_DecodedData, Key);

            if ((prevBL != null) && (prevBL.Type == BootloaderType.CF))
            {
                Key = Utils.GetBytes(Data, 0x330, 0x10);
            }

            IsEncrypted = true;
        }

        public void Decrypt(Bootloader prevBL = null, byte[] cpuKey = null)
        {
            if (!IsEncrypted) return;

            byte[] _salt = Salt;
            byte[] _prevKey = (prevBL != null) ? prevBL.Key : Globals._1BLKey;

            if ((prevBL != null) && (prevBL.Type == BootloaderType.CB) && (Type == BootloaderType.CB))
            {
                PrintDebug("CB Is split");
                _salt = Utils.ConcatByteArrays(_salt, cpuKey);

                //New CB Encryption Scheme
                if ((Utils.GetInt(Data, 0x6, 2) & 0x1000) != 0)
                {
                    PrintDebug("CB New Encryption Scheme");
                    byte[] _2BLHeader = prevBL.Header;
                    _2BLHeader[0x6] = 0x00;
                    _2BLHeader[0x7] = 0x00;
                    _salt = Utils.ConcatByteArrays(_salt, _2BLHeader);
                }
            }

            Key = Utils.GetHMACKey(_prevKey, _salt);

            if ((prevBL != null) && (prevBL.Type == BootloaderType.CF))
            {
                Key = Utils.GetBytes(Data, 0x330, 0x10);
            }

            _DecodedData = RC4.Apply(_EncodedData, Key);

            IsEncrypted = false;

        }

        private byte GetSaltOffset(BootloaderType type)
        {
            byte _saltOffset;

            switch (type)
            {
                case BootloaderType.CF:
                    _saltOffset = 0x20;
                    break;
                default:
                    _saltOffset = 0x10; // Default salt offset
                    break;
            }

            return _saltOffset;

        }

        public void DecryptPatchSlot()
        {
            //TODO: maybe different decrypt for patchslots?
        }
    }
}
