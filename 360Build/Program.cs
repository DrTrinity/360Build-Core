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
            Nand nand = new Nand("C:\\Users\\EH Home\\Desktop\\updflashsplit.bin", "8ECD51A961515CDF48CC4D1CDE310248");
            File.WriteAllBytes("C:\\Users\\EH Home\\Desktop\\CB_A." + nand._2BL.Version + ".bin", nand._2BL.Data);
            File.WriteAllBytes("C:\\Users\\EH Home\\Desktop\\CB_B." + nand._3BL.Version + ".bin", nand._3BL.Data);
            File.WriteAllBytes("C:\\Users\\EH Home\\Desktop\\CD." + nand._4BL.Version + ".bin", nand._4BL.Data);
            File.WriteAllBytes("C:\\Users\\EH Home\\Desktop\\CE." + nand._5BL.Version + ".bin", nand._5BL.Data);
            File.WriteAllBytes("C:\\Users\\EH Home\\Desktop\\CF0." + nand._6BL.Version + ".bin", nand._6BL.Data);
            File.WriteAllBytes("C:\\Users\\EH Home\\Desktop\\CG0." + nand._7BL.Version + ".bin", nand._7BL.Data);
            Console.ReadKey();
        }
    }
}
