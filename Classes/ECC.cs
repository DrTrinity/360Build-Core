namespace _360Build_Core.Classes;

public class ECC
{
    public List<SpareData> _SpareData { get; set; }
    
    public enum SpareDataType
    {
        NONE,
        SMALL,
        BIG_ON_SMALL,
        BIG
    };

    public class SpareData
    {
        public byte[] Data { get; set; }
        
        public short BlockId { get; set; }
        public bool BadBlock { get; set; }
        public int FsSequence { get; set; }
        public short FsSize { get; set; }
        public byte FsPageCount { get; set; }
        public byte FsBlockType { get; set; }
        public byte[] EDC { get; set; }
        
        public SpareData(byte[] data)
        {
            Data = data;
            BlockId = BitConverter.ToInt16(data, 0);
        }
    }

    internal void LoadSpareData(byte[] nanddata)
    {
        _SpareData = new List<SpareData>();
        int pageCount = nanddata.Length / 0x210;

        for (int i = 1; i <= pageCount; i++)
        {
            _SpareData.Add(new SpareData(Utils.GetBytes(nanddata, (i * 0x210) - 0x10, 0x10)));
        }
    }

    internal static SpareDataType GetSpareDataType(byte[] nanddata)
    {
        byte[] spareData = Utils.GetBytes(nanddata, 0x200, 0x10);

        if (spareData[0] == 0xFF)
        {
            return SpareDataType.BIG;
        }
        else if (spareData[5] == 0xFF)
        {
            return SpareDataType.SMALL;
        }
        else if (spareData[1] == 1)
        {
            return SpareDataType.BIG_ON_SMALL;
        }
        else
        {
            return SpareDataType.NONE;
        }
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

    internal static byte[] AddEcc(byte[] data, SpareDataType blockType = SpareDataType.BIG_ON_SMALL)
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
                    if (blockType == SpareDataType.BIG_ON_SMALL)
                    {
                        bw.Write((byte)0);
                        bw.Write((uint)(block / 32));
                        bw.Write(new byte[] { 0xFF, 0, 0 });
                    }
                    else if (blockType == SpareDataType.BIG)
                    {
                        bw.Write((byte)0xFF);
                        bw.Write((uint)(block / 256));
                        bw.Write(new byte[] { 0, 0, 0 });
                    }
                    else if (blockType == SpareDataType.SMALL)
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
}