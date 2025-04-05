using System.Collections;
using _360Build_Core.Exceptions;

namespace _360Build_Core.Classes;

public class Patchslot : IEnumerable<Bootloader>
{
    public byte[] Data { get; set; }
    public int Length { get; set; }
    public Bootloader CfSf { get; set; }
    public Bootloader CgSg { get; set; }

    public Patchslot(byte[] data, int offset, int length = 0x10000)
    {
        try
        {
            Length = length;
            CfSf = Bootloader.Create(data, offset, (Bootloader.BootloaderType)Utils.GetInt(data, offset, 2));
            CgSg = Bootloader.Create(data, offset + CfSf.Length, (Bootloader.BootloaderType)Utils.GetInt(data, offset + CfSf.Length, 2));
        }
        catch (InvalidBootloaderException e)
        {
            throw new InvalidPatchslotException("A patchslot is invalid due to invalid bootloader");
        }
    }
    
    public IEnumerator<Bootloader> GetEnumerator()
    {
        yield return CfSf;
        yield return CgSg;
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}