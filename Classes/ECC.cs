namespace _360Build_Core.Classes;

public class Ecc
{
    public List<SpareData> SpareDatas { get; set; }

    internal void LoadSpareData(byte[]? nanddata)
    {
        SpareDatas = new List<SpareData>();
        var pageCount = nanddata.Length / 0x210;

        for (var i = 1; i <= pageCount; i++)
            SpareDatas.Add(new SpareData(Utils.GetBytes(nanddata, i * 0x210 - 0x10, 0x10)));
    }

    internal static XboxRom.BlockType GetSpareDataType(byte[]? nanddata)
    {
        var spareData = Utils.GetBytes(nanddata, 0x200, 0x10);

        if (spareData[0] == 0xFF) return XboxRom.BlockType.Big;

        if (spareData[5] == 0xFF) return XboxRom.BlockType.Small;

        if (spareData[1] == 1) return XboxRom.BlockType.BigOnSmall;

        return XboxRom.BlockType.None;
    }

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

    internal static byte[] AddEcc(byte[] data, XboxRom.BlockType blockType = XboxRom.BlockType.BigOnSmall)
    {
        using (var rms = new MemoryStream(data))
        using (var wms = new MemoryStream())
        {
            var block = 0;
            while (rms.Position < data.Length)
            {
                var buff = new byte[528];
                rms.Read(buff, 0, 512);

                using (var ms = new MemoryStream(buff))
                using (var bw = new BinaryWriter(ms))
                {
                    ms.Seek(512, SeekOrigin.Begin);
                    if (blockType == XboxRom.BlockType.BigOnSmall)
                    {
                        bw.Write((byte)0);
                        bw.Write((uint)(block / 32));
                        bw.Write(new byte[] { 0xFF, 0, 0 });
                    }
                    else if (blockType == XboxRom.BlockType.Big)
                    {
                        bw.Write((byte)0xFF);
                        bw.Write((uint)(block / 256));
                        bw.Write(new byte[] { 0, 0, 0 });
                    }
                    else if (blockType == XboxRom.BlockType.Small)
                    {
                        bw.Write((uint)(block / 32));
                        bw.Write(new byte[] { 0, 0xFF, 0, 0 });
                    }
                    else
                    {
                        return null;
                    }

                    buff = ms.ToArray();
                }

                Buffer.BlockCopy(BitConverter.GetBytes(CalcEcc(buff)), 0, buff, 524, 4);
                block++;
                wms.Write(buff, 0, buff.Length);
            }

            return wms.ToArray();
        }
    }

    internal static byte[]? UnEcc(byte[]? data)
    {
        using (var rms = new MemoryStream(data))
        using (var wms = new MemoryStream())
        {
            for (var i = 0; i < data.Length / 528; i++)
            {
                var buff = new byte[512];
                rms.Read(buff, 0, buff.Length);
                rms.Seek(0x10, SeekOrigin.Current);
                wms.Write(buff, 0, buff.Length);
            }

            return wms.ToArray();
        }
    }

    public class SpareData
    {
        public enum SpareDataBlockType : byte
        {
            FsRootEntry     = 0x30,
            FsRootEntryAlt  = 0x2C,
            MobileB         = 0x31,
            MobileC         = 0x32,
            MobileD         = 0x33,
            MobileE         = 0x34,
            MobileF         = 0x35,
            MobileG         = 0x36,
            MobileH         = 0x37,
            MobileI         = 0x38,
            MobileJ         = 0x39,
            InvalidMobileJ  = 0x40, 
            InUseMobileJ    = 0x80  
        }
        
        public SpareData(byte[]? data)
        {
            Data = data;
            BlockId = (ushort)(((data[1] & 0x0F) << 8) | data[0]);
            FsSequence = data[2] | (data[3] << 8) | (data[4] << 16) | (data[6] << 24);
            BadBlock = data[5] != 0xFF;
            FsSize = (ushort)((data[8] << 8) | data[7]);
            FsPageCount = data[9];
            FsBlockType = (SpareDataBlockType)(data[12] & 0x3F);
            Edc = Utils.GetBytes(data, 13, 3);
        }

        public byte[]? Data { get; set; }

        public ushort BlockId { get; set; }
        public bool BadBlock { get; set; }
        public int FsSequence { get; set; }
        public ushort FsSize { get; set; }
        public byte FsPageCount { get; set; }
        public SpareDataBlockType FsBlockType { get; set; }
        public byte[] Edc { get; set; }
    }
}