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
        public byte[] _2BLOffset { get; set; }
        public byte[] _6BLOffset { get; set; }
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
            Version = Utils.ByteArrayToInt(Utils.ReturnPortion(Data, 0x2, 2));
            Length = Data.Length;
            _2BLOffset = Utils.ReturnPortion(Data, 0x8, 4);
            _6BLOffset = Utils.ReturnPortion(Data, 0xC, 4);
            KVOffset = Utils.ReturnPortion(Data, 0x6C, 4);
            SMCOffset = Utils.ReturnPortion(Data, 0x7C, 4);
            SMCLength = Utils.ReturnPortion(Data, 0x78, 4);

            //2BL Decryption
            byte[] _2BLlength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_2BLOffset) + 0xC, 4);
            byte[] _2BLsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_2BLOffset) + 0x10, 0x10);
            byte[] _2BLkey = Utils.ReturnPortion(new HMACSHA1(_1BLKey).ComputeHash(_2BLsalt), 0, 0x10);
            byte[] _2BLfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_2BLOffset) + 0x20, Utils.ByteArrayToInt(_2BLlength) - 0x20);
            byte[] _2BLdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_2BLOffset), 0x10), _2BLkey, RC4.Apply(_2BLfordec, _2BLkey));
            _2BL = new Bootloader(_2BLdecrypted);

            //3BL Decryption
            byte[] _3BLOffset = BitConverter.GetBytes(Utils.ByteArrayToInt(_2BLOffset) + Utils.ByteArrayToInt(_2BLlength));
            Array.Reverse(_3BLOffset);
            byte[] _3BLlength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_3BLOffset) + 0xC, 4);
            byte[] _3BLsalt = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_3BLOffset) + 0x10, 0x10), CPUKey);
            byte[] _3BLkey = Utils.ReturnPortion(new HMACSHA1(_2BLkey).ComputeHash(_3BLsalt), 0, 0x10);

            bool CBSplit = (Utils.ByteArrayToString(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_3BLOffset), 2)) == "4342");

            if (CBSplit)
            {
                //New CB Encryption Scheme
                if ((Utils.ByteArrayToInt(Utils.ReturnPortion(_2BL.Data, 0x6, 2)) & 0x1000) != 0)
                {
                    byte[] _2BLHeader = Utils.ReturnPortion(_2BL.Data, 0, 0x10);
                    _2BLHeader[0x6] = 0x00;
                    _2BLHeader[0x7] = 0x00;
                    _3BLsalt = Utils.ConcatByteArrays(_3BLsalt, _2BLHeader);
                    _3BLkey = Utils.ReturnPortion(new HMACSHA1(_2BLkey).ComputeHash(_3BLsalt), 0, 0x10);
                }

                byte[] _3BLfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_3BLOffset) + 0x20, Utils.ByteArrayToInt(_3BLlength) - 0x20);
                byte[] _3BLdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_3BLOffset), 0x10), _3BLkey, RC4.Apply(_3BLfordec, _3BLkey));
                _3BL = new Bootloader(_3BLdecrypted);
            }

            //4BL Decryption
            byte[] _4BLOffset = BitConverter.GetBytes(Utils.ByteArrayToInt(CBSplit ? _3BLOffset : _2BLOffset) + Utils.ByteArrayToInt(CBSplit ? _3BLlength : _2BLlength));
            Array.Reverse(_4BLOffset);
            byte[] _4BLlength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_4BLOffset) + 0xC, 4);
            byte[] _4BLsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_4BLOffset) + 0x10, 0x10);
            byte[] _4BLkey = Utils.ReturnPortion(new HMACSHA1(CBSplit ? _3BLkey : _2BLkey).ComputeHash(_4BLsalt), 0, 0x10);
            byte[] _4BLfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_4BLOffset) + 0x20, Utils.ByteArrayToInt(_4BLlength) - 0x20);
            byte[] _4BLdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_4BLOffset), 0x10), _4BLkey, RC4.Apply(_4BLfordec, _4BLkey));
            _4BL = new Bootloader(_4BLdecrypted);

            //5BL Decryption (Padding Needs to be added to the end)
            byte[] _5BLOffset = BitConverter.GetBytes(Utils.ByteArrayToInt(_4BLOffset) + Utils.ByteArrayToInt(_4BLlength));
            Array.Reverse(_5BLOffset);
            byte[] _5BLlength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_5BLOffset) + 0xC, 4);
            byte[] _5BLsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_5BLOffset) + 0x10, 0x10);
            byte[] _5BLkey = Utils.ReturnPortion(new HMACSHA1(_4BLkey).ComputeHash(_5BLsalt), 0, 0x10);
            byte[] _5BLfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_5BLOffset) + 0x20, Utils.ByteArrayToInt(_5BLlength) - 0x20);
            byte[] _5BLdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_5BLOffset), 0x10), _5BLkey, RC4.Apply(_5BLfordec, _5BLkey));
            _5BL = new Bootloader(_5BLdecrypted);

            //6BL Decryption
            byte[] _6BLlength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_6BLOffset) + 0xC, 4);
            byte[] _6BLsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_6BLOffset) + 0x20, 0x10);
            byte[] _6BLkey = Utils.ReturnPortion(new HMACSHA1(_1BLKey).ComputeHash(_6BLsalt), 0, 0x10);
            byte[] _6BLfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_6BLOffset) + 0x30, Utils.ByteArrayToInt(_6BLlength) - 0x30);
            byte[] _6BLdecrypted = RC4.Apply(_6BLfordec, _6BLkey);
            byte[] KeyFor7BL = Utils.ReturnPortion(_6BLdecrypted, 0x300, 0x10);
            byte[] _6BLdecryptedFinal = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_6BLOffset), 0x20), KeyFor7BL, _6BLdecrypted);
            _6BL = new Bootloader(_6BLdecryptedFinal);


            //7BL Decryption
            byte[] _7BLOffset = BitConverter.GetBytes(Utils.ByteArrayToInt(_6BLOffset) + Utils.ByteArrayToInt(_6BLlength));
            Array.Reverse(_7BLOffset);
            byte[] _7BLlength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_7BLOffset) + 0xC, 4);
            byte[] _7BLsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_7BLOffset) + 0x10, 0x10);
            byte[] _7BLkey = Utils.ReturnPortion(new HMACSHA1(KeyFor7BL).ComputeHash(_7BLsalt), 0, 0x10);
            byte[] _7BLfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_7BLOffset) + 0x20, Utils.ByteArrayToInt(_7BLlength) - 0x20);
            byte[] _7BLdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_7BLOffset), 0x10), _7BLkey, RC4.Apply(_7BLfordec, _7BLkey));
            _7BL = new Bootloader(_7BLdecrypted);

            //8BL Decryption
            byte[] _8BLOffset = BitConverter.GetBytes(Utils.ByteArrayToInt(_6BLOffset) + 0x10000);
            Array.Reverse(_8BLOffset);
            byte[] _8BLlength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_8BLOffset) + 0xC, 4);
            byte[] _8BLsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_8BLOffset) + 0x20, 0x10);
            byte[] _8BLkey = Utils.ReturnPortion(new HMACSHA1(_1BLKey).ComputeHash(_8BLsalt), 0, 0x10);
            byte[] _8BLfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_8BLOffset) + 0x30, Utils.ByteArrayToInt(_8BLlength) - 0x30);
            byte[] _8BLdecrypted = RC4.Apply(_8BLfordec, _8BLkey);
            byte[] KeyFor9BL = Utils.ReturnPortion(_8BLdecrypted, 0x300, 0x10);
            byte[] _8BLdecryptedFinal = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_8BLOffset), 0x20), KeyFor9BL, _8BLdecrypted);
            _8BL = new Bootloader(_8BLdecryptedFinal);


            //9BL Decryption
            byte[] _9BLOffset = BitConverter.GetBytes(Utils.ByteArrayToInt(_8BLOffset) + Utils.ByteArrayToInt(_8BLlength));
            Array.Reverse(_9BLOffset);
            byte[] _9BLlength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_9BLOffset) + 0xC, 4);
            byte[] _9BLsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_9BLOffset) + 0x10, 0x10);
            byte[] _9BLkey = Utils.ReturnPortion(new HMACSHA1(KeyFor9BL).ComputeHash(_9BLsalt), 0, 0x10);
            byte[] _9BLfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_9BLOffset) + 0x20, Utils.ByteArrayToInt(_9BLlength) - 0x20);
            byte[] _9BLdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(_9BLOffset), 0x10), _9BLkey, RC4.Apply(_9BLfordec, _9BLkey));
            _9BL = new Bootloader(_9BLdecrypted);
        }

    }
}
