/*******
* Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
* Date: July 2016
* 
* This can be used to decompress a file using the ZLIB/deflate algorithm
* C# implementation preliminary done before we actually manage to do it in Python :)
* This mimics a call to uncompress("deflate") in Flash
* http://help.adobe.com/en_US/as3/dev/WS5b3ccc516d4fbf351e63e3d118666ade46-7d53.html
********/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO.Compression;

// adapted from http://stackoverflow.com/questions/1528508/uncompress-data-file-with-deflatestream
namespace Uncompress
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: Uncompress <infile> <outfile>");
                Console.WriteLine("\tEg: Uncompress 4_res_js_rc4.txt 4_res_js_rc4_decompressed.txt");
                return;
            }
            String inName = args[0];
            String outName = args[1];
            Stream inp = new FileStream(inName, FileMode.Open, FileAccess.Read);
            Stream outp = new FileStream(outName, FileMode.Create, FileAccess.Write);
            long nBytes = Decompress(inp, outp);
            inp.Close();
            outp.Close();
            Console.WriteLine("Written {0:D}", nBytes);
        }

        static public long Decompress(Stream inp, Stream outp)
        {
            byte[] buf = new byte[1024];
            long nBytes = 0;

            // Decompress the contents of the input file, keeping the underlying input stream open
            inp = new DeflateStream(inp, CompressionMode.Decompress, true);

            int len;
            while ((len = inp.Read(buf, 0, buf.Length)) > 0)
            {
                outp.Write(buf, 0, len);
                nBytes += len;
            }
            outp.Flush();
            return nBytes;
        }
    }
}
