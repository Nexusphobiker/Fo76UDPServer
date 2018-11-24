using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fo76UDPServer.Messages
{
    class ChangeCipherSpecMessage
    {
        public bool IsValid;
        public byte Unk1;

        public ChangeCipherSpecMessage(byte[] data)
        {
            if (data.Length < 1)
            {
                IsValid = false;
                Console.WriteLine("Dropping packet " + Helpers.ByteArrayToString(data) + " Invalid length");
                return;
            }

            MemoryStream stream = new MemoryStream(data);
            this.Unk1 = (byte)stream.ReadByte();


            stream.Close();
            IsValid = true;
        }

        public override string ToString()
        {
            if (!IsValid)
                return "Invalid packet";
            return "Unk1:" + Unk1.ToString("X");
        }

        public static byte[] BuildChangeCipherSpecMessageResponse()
        {
            byte[] fillIn = { 0x14, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01 };
            return fillIn;
        }
    }
}
