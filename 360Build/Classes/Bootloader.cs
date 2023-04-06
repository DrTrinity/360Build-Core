using RC4Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _360Build
{
    internal class Bootloader
    {
        public byte[] Data
        {
            get { return Utils.ConcatByteArrays(Header, Key, _DecodedData); }
        }
        public byte[] Header { get; set; }
        public byte[] Key { get; set; }
        public int EntrypointOffset { get; set; }
        public int Length { get; set; }
        public int Version { get; set; }
        public int LDV { get; set; }

        private byte[] _EncodedData { get; set; }
        private byte[] _DecodedData { get; set; }
        private int _HeaderLength { get; set; }

        public Bootloader(byte[] encData, int offset, int headerLength = 0x10)
        {
            EntrypointOffset = Utils.GetInt(encData, offset + 0x8, 4);
            Length = Utils.GetInt(encData, offset + 0xC, 4);
            Version = Utils.GetInt(encData, offset + 0x2, 2);
            Header = Utils.GetBytes(encData, offset, headerLength);

            _EncodedData = Utils.GetBytes(encData, offset + headerLength + 0x10, Length - headerLength - 0x10);
            _HeaderLength = headerLength;
        }
        
        public void decrypt(byte[] key)
        {
            Key = key;
            _DecodedData = RC4.Apply(_EncodedData, key);
        }

        public void decryptPatchSlot()
        {
            //TODO: maybe different decrypt for patchslots?
        }
    }
}
