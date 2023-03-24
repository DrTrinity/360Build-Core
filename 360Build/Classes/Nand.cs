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
        public byte[] CBOffset { get; set; }
        public byte[] CFOffset { get; set; }
        public byte[] KVOffset { get; set; }
        public byte[] SMCOffset { get; set; }
        public byte[] SMCLength { get; set; }

        public Bootloader CB;
        public Bootloader CD;
        public Bootloader CE;
        public Bootloader CF;
        public Bootloader CG;

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
            CBOffset = Utils.ReturnPortion(Data, 0x8, 4);
            CFOffset = Utils.ReturnPortion(Data, 0xC, 4);
            KVOffset = Utils.ReturnPortion(Data, 0x6C, 4);
            SMCOffset = Utils.ReturnPortion(Data, 0x7C, 4);
            SMCLength = Utils.ReturnPortion(Data, 0x78, 4);

            //CB Decryption
            byte[] CBLength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CBOffset) + 0xC, 4);
            byte[] CBsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CBOffset) + 0x10, 0x10);
            byte[] CBkey = Utils.ReturnPortion(new HMACSHA1(_1BLKey).ComputeHash(CBsalt), 0, 0x10);
            byte[] CBfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CBOffset) + 0x20, Utils.ByteArrayToInt(CBLength) - 0x20);
            byte[] CBdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CBOffset), 0x10), CBkey, RC4.Apply(CBfordec, CBkey));
            CB = new Bootloader(CBdecrypted);

            //CD Decryption
            byte[] CDOffset = BitConverter.GetBytes(Utils.ByteArrayToInt(CBOffset) + Utils.ByteArrayToInt(CBLength));
            Array.Reverse(CDOffset);
            byte[] CDLength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CDOffset) + 0xC, 4);
            byte[] CDsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CDOffset) + 0x10, 0x10);
            byte[] CDkey = Utils.ReturnPortion(new HMACSHA1(CBkey).ComputeHash(CDsalt), 0, 0x10);
            byte[] CDfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CDOffset) + 0x20, Utils.ByteArrayToInt(CDLength) - 0x20);
            byte[] CDdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CDOffset), 0x10), CDkey, RC4.Apply(CDfordec, CDkey));
            CD = new Bootloader(CDdecrypted);

            //CE Decryption
            byte[] CEOffset = BitConverter.GetBytes(Utils.ByteArrayToInt(CDOffset) + Utils.ByteArrayToInt(CDLength));
            Array.Reverse(CEOffset);
            byte[] CELength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CEOffset) + 0xC, 4);
            byte[] CEsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CEOffset) + 0x10, 0x10);
            byte[] CEkey = Utils.ReturnPortion(new HMACSHA1(CDkey).ComputeHash(CEsalt), 0, 0x10);
            byte[] CEfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CEOffset) + 0x20, Utils.ByteArrayToInt(CELength) - 0x20);
            byte[] CEdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CEOffset), 0x10), CEkey, RC4.Apply(CEfordec, CEkey));
            CE = new Bootloader(CEdecrypted);

            //CF Decryption
            byte[] CFLength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CFOffset) + 0xC, 4);
            byte[] CFsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CFOffset) + 0x20, 0x10);
            byte[] CFkey = Utils.ReturnPortion(new HMACSHA1(_1BLKey).ComputeHash(CFsalt), 0, 0x10);
            byte[] CFfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CFOffset) + 0x30, Utils.ByteArrayToInt(CFLength) - 0x30);
            byte[] CFdecrypted = RC4.Apply(CFfordec, CFkey);
            byte[] KeyForCG = Utils.ReturnPortion(CFdecrypted, 0x300, 0x10);
            byte[] CEdecryptedFinal = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CFOffset), 0x20), KeyForCG, CFdecrypted);
            CF = new Bootloader(CEdecryptedFinal);


            //CG Decryption
            byte[] CGOffset = BitConverter.GetBytes(Utils.ByteArrayToInt(CFOffset) + Utils.ByteArrayToInt(CFLength));
            Array.Reverse(CGOffset);
            byte[] CGLength = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CGOffset) + 0xC, 4);
            byte[] CGsalt = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CGOffset) + 0x10, 0x10);
            byte[] CGkey = Utils.ReturnPortion(new HMACSHA1(KeyForCG).ComputeHash(CGsalt), 0, 0x10);
            byte[] CGfordec = Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CGOffset) + 0x20, Utils.ByteArrayToInt(CGLength) - 0x20);
            byte[] CGdecrypted = Utils.ConcatByteArrays(Utils.ReturnPortion(Data, Utils.ByteArrayToInt(CGOffset), 0x10), CGkey, RC4.Apply(CGfordec, CGkey));
            CG = new Bootloader(CGdecrypted);

        }

    }
}
