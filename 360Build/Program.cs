using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace _360Build
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Nand nand = new Nand("C:\\Users\\EH Home\\Desktop\\updflash.bin", "");
            Console.WriteLine(Utils.ByteArrayToString(Utils.ReturnPortion(nand.CG.Data, 0x10, 0x10)));
            //File.WriteAllBytes("C:\\Users\\EH Home\\Desktop\\updflash.raw", nand.Data);
            Console.ReadKey();
        }
    }
}
