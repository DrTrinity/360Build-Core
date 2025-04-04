using _360Build_Core.Exceptions;

namespace _360Build_Core.Classes;

public class Patchslot
{
    public byte[] Data { get; set; }
    public List<Bootloader> Bootloaders = new List<Bootloader>(2);

    public Patchslot(byte[] data, int offset, int length)
    {
        
    }
}