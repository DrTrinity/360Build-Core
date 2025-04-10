using System.Text;
using _360Build_Core.Exceptions;

namespace _360Build_Core.Classes;

public class Filesystem
{
    public Filesystem(byte[]? encData, int offset, int version, XboxRom rom = null, int length = 0x4000)
    {
        Data = Utils.GetBytes(encData, offset, length);
        Rom = rom;
        Version = version;
        Length = length;
        BlockMaps = new List<byte[]>();
        EntryPages = new List<byte[]>();
        Entries = new List<FilesystemEntry>();

        for (var i = 0; i < length / 0x200; i++)
            if (i % 2 == 0) BlockMaps.Add(Utils.GetBytes(Data, i * 0x200, 0x200));
            else EntryPages.Add(Utils.GetBytes(Data, i * 0x200, 0x200));

        foreach (var ep in EntryPages)
            for (var i = 0; i < ep.Length / 0x20; i++)
                try
                {
                    Entries.Add(new FilesystemEntry(Utils.GetBytes(ep, i * 0x20, 0x20), this));
                }
                catch (InvalidFilesystemEntryException ex)
                {
                    Logger.LogDebug(ex.Message);
                }
    }

    public byte[] Data { get; set; }
    public int Version { get; set; }
    public int Length { get; set; }
    public XboxRom Rom { get; set; }
    public bool IsCurrent { get; set; } = false;
    public List<byte[]> BlockMaps { get; set; }
    public List<byte[]> EntryPages { get; set; }
    public List<FilesystemEntry> Entries { get; set; }

    public class FilesystemEntry
    {
        public FilesystemEntry(byte[] data, Filesystem parent)
        {
            if (data.All(d => d == 0)) throw new InvalidFilesystemEntryException("Filesystem entry is empty. Skipping...");

            Data = data;
            Parent = parent;
            Deleted = data[0] == 0x5;
            FileName = Encoding.ASCII.GetString(Utils.GetBytes(data, 0, 0x14)).TrimEnd('\0');
            BlockLocation = (ushort)Utils.GetInt(data, 0x16, 2);
            FileSize = (uint)Utils.GetInt(data, 0x18, 4);
            Timestamp = Utils.DosDateToDateTime((uint)Utils.GetInt(data, 0x1C, 4));
        }

        private Filesystem Parent;
        public byte[] Data { get; set; }
        public string FileName { get; set; }
        public bool Deleted { get; set; } = false;
        public ushort BlockLocation { get; set; }
        public uint FileSize { get; set; }
        public DateTime Timestamp { get; set; }
        
        public void Dump(string path)
        {
            byte[] file = Utils.GetBytes(Parent.Rom.Data, BlockLocation * Parent.Rom.BlockSize, (int)FileSize);
            File.WriteAllBytes(path, file);
        }
    }
}