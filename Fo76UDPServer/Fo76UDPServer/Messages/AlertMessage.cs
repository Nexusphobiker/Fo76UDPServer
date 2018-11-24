using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fo76UDPServer.Messages
{
    class AlertMessage
    {
        public bool IsValid;
        public byte Unk1;
        public byte Unk2;

        public AlertMessage(byte[] data)
        {
            if (data.Length < 2)
            {
                IsValid = false;
                Console.WriteLine("Dropping packet " + Helpers.ByteArrayToString(data) + " Invalid length");
                return;
            }

            MemoryStream stream = new MemoryStream(data);
            this.Unk1 = (byte)stream.ReadByte();
            this.Unk2 = (byte)stream.ReadByte();


            stream.Close();
            IsValid = true;
        }

        public override string ToString()
        {
            if (!IsValid)
                return "Invalid packet";
            return "Unk1:"+Unk1.ToString("X")+" Unk2:"+Unk2.ToString("X");
        }
    }
}
