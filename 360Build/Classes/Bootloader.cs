using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _360Build
{
    internal class Bootloader
    {
        public byte[] Data { get; set; }
        public byte[] EntrypointOffset { get; set; }
        public byte[] Length { get; set; }
        public int Version { get; set; }
        public int LDV { get; set; }

        public Bootloader(byte[] data)
        {
            this.Data = data;
            EntrypointOffset = Utils.ReturnPortion(Data, 0x8, 4);
            Length = Utils.ReturnPortion(Data, 0xC, 4);
            Version = Utils.ByteArrayToInt(Utils.ReturnPortion(Data, 0x2, 2));
        }
    }
}
