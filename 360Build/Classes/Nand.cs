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
    internal class Nand
    {
        private readonly byte[] _1BLKey = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };
        public byte[] CPUKey { get; set; }

        public byte[] Data { get; set; }
        public int Length { get; set; }
        public int Version { get; set; }
        public int _2BLOffset { get; set; }
        public int _6BLOffset { get; set; }
        public byte[] KVOffset { get; set; }
        public byte[] SMCOffset { get; set; }
        public byte[] SMCLength { get; set; }

        public Bootloader _2BL; //CB, CB_A 
        public Bootloader _3BL; //CB_B if present
        public Bootloader _4BL; //CD
        public Bootloader _5BL; //CE
        public Bootloader _6BL; //CF0 if present
        public Bootloader _7BL; //CG0 if present
        public Bootloader _8BL; //CF1 if present
        public Bootloader _9BL; //CG1 if present

        public Nand(string path, string CPUKey)
        {
            this.CPUKey = Utils.StringToByteArray(CPUKey);
            Data = File.ReadAllBytes(path);

            deconstruct();
        }

        //I know. Its a mess :)
        private void deconstruct()
        {
            //Strip ECC
            Data = Utils.UnEcc(Data);

            //Set Variables
            Version = Utils.GetInt(Data, 0x2, 2);
            Length = Data.Length;
            _2BLOffset = Utils.GetInt(Data, 0x8, 4);
            _6BLOffset = Utils.GetInt(Data, 0xC, 4);
            KVOffset = Utils.ReturnPortion(Data, 0x6C, 4);
            SMCOffset = Utils.ReturnPortion(Data, 0x7C, 4);
            SMCLength = Utils.ReturnPortion(Data, 0x78, 4);


            //2BL Decryption
            byte[] _2BLsalt = Utils.ReturnPortion(Data, _2BLOffset + 0x10, 0x10);
            byte[] _2BLkey = Utils.GetHMACKey(_1BLKey, _2BLsalt);
            _2BL = new Bootloader(Data, _2BLOffset);
            _2BL.decrypt(_2BLkey);


            //3BL Decryption
            int _3BLOffset = _2BLOffset + _2BL.Length;
            byte[] _3BLkey = {};
            bool CBSplit = Utils.GetInt(Data, _3BLOffset, 2) == 0x4342;

            if (CBSplit)
            {
                byte[] _3BLsalt = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, _3BLOffset + 0x10, 0x10), CPUKey);

                //New CB Encryption Scheme
                if ((Utils.GetInt(_2BL.Data, 0x6, 2) & 0x1000) != 0)
                {
                    // TODO: check if _2BL.Header is reference or copy
                    // IDEA: _2BL.Header & 0b0
                    byte[] _2BLHeader = Utils.ReturnPortion(_2BL.Data, 0, 0x10);
                    _2BLHeader[0x6] = 0x00;
                    _2BLHeader[0x7] = 0x00;
                    _3BLsalt = Utils.ConcatByteArrays(_3BLsalt, _2BLHeader);
                }

                _3BLkey = Utils.GetHMACKey(_2BLkey, _3BLsalt);
                _3BL = new Bootloader(Data, _3BLOffset);
                _3BL.decrypt(_3BLkey);
            }


            //4BL Decryption
            int _4BLOffset = CBSplit ? _3BLOffset + _3BL.Length : _2BLOffset + _2BL.Length;
            byte[] _4BLsalt = Utils.ReturnPortion(Data, _4BLOffset + 0x10, 0x10);
            byte[] _4BLkey = Utils.GetHMACKey(CBSplit ? _3BLkey : _2BLkey, _4BLsalt);
            _4BL = new Bootloader(Data, _4BLOffset);
            _4BL.decrypt(_4BLkey);


            //5BL Decryption (Padding Needs to be added to the end)
            int _5BLOffset = _4BLOffset + _4BL.Length;
            byte[] _5BLsalt = Utils.ReturnPortion(Data, _5BLOffset + 0x10, 0x10);
            byte[] _5BLkey = Utils.GetHMACKey(_4BLkey, _5BLsalt);
            _5BL = new Bootloader(Data, _5BLOffset);
            _5BL.decrypt(_5BLkey);


            //6BL Decryption
            byte[] _6BLsalt = Utils.ReturnPortion(Data, _6BLOffset + 0x20, 0x10);
            byte[] _6BLkey = Utils.GetHMACKey(_1BLKey, _6BLsalt);
            _6BL = new Bootloader(Data, _6BLOffset, 0x20);
            _6BL.decrypt(_6BLkey);
            _6BL.Key = Utils.ReturnPortion(_6BL.Data, 0x300, 0x10);
            // TODO: fix key assignment


            //7BL Decryption
            int _7BLOffset = _6BLOffset + _6BL.Length;
            byte[] _7BLsalt = Utils.ReturnPortion(Data, _7BLOffset + 0x10, 0x10);
            byte[] _7BLkey = Utils.GetHMACKey(_6BL.Key, _7BLsalt);
            _7BL = new Bootloader(Data, _7BLOffset);
            _7BL.decrypt(_7BLkey);


            //8BL Decryption
            int _8BLOffset = _6BLOffset + 0x10000;
            byte[] _8BLsalt = Utils.ReturnPortion(Data, _8BLOffset + 0x20, 0x10);
            byte[] _8BLkey = Utils.GetHMACKey(_1BLKey, _8BLsalt);
            _8BL = new Bootloader(Data, _8BLOffset, 0x20);
            _8BL.decrypt(_8BLkey);
            _8BL.Key = Utils.ReturnPortion(_8BL.Data, 0x300, 0x10);
            // TODO: fix key assignment


            //9BL Decryption
            int _9BLOffset = _8BLOffset + _8BL.Length;
            byte[] _9BLsalt = Utils.ReturnPortion(Data, _9BLOffset + 0x10, 0x10);
            byte[] _9BLkey = Utils.GetHMACKey(_8BL.Key, _9BLsalt);
            _9BL = new Bootloader(Data, _9BLOffset);
            _9BL.decrypt(_9BLkey);
        }

    }
}
