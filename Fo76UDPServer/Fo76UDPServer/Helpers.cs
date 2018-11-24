using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fo76UDPServer
{
    class Helpers
    {
        public static string ByteArrayToString(byte[] data)
        {
            string retVar = "";
            foreach (var i in data)
            {
                if (i.ToString("X").Length < 2)
                    retVar = retVar + "0" + i.ToString("X") + " ";
                else
                    retVar = retVar + i.ToString("X") + " ";
            }
            return retVar;
        }

        private static Random random = new Random();
        public static byte[] GenRandomBytes(int num)
        {
            byte[] retVar = new byte[num];
            random.NextBytes(retVar);
            return retVar;
        }
    }

    public static class StreamExtensions
    {
        public static short ReadLittleEndianShort(this Stream input)
        {
            byte[] shortBuff = new byte[2];
            input.Read(shortBuff, 0, shortBuff.Length);
            shortBuff = shortBuff.Reverse().ToArray();
            return BitConverter.ToInt16(shortBuff, 0);
        }

        public static long ReadLittleEndianID(this Stream input)
        {
            byte[] IDBuff = new byte[8];
            input.Read(IDBuff, 2, 6);
            IDBuff = IDBuff.Reverse().ToArray();
            return BitConverter.ToInt64(IDBuff, 0);
        }

        public static int ReadLittleEndian3Bytes(this Stream input)
        {
            byte[] intBuff = new byte[4];
            input.Read(intBuff, 1, 3);
            intBuff = intBuff.Reverse().ToArray();
            return BitConverter.ToInt32(intBuff, 0);
        }
    }
}
