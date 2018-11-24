using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fo76UDPServer
{
    class Packet
    {
        public bool IsValid;

        public PacketType Type;
        public short Unk;
        public short IsEncrypted;
        public long ID;
        public short BodySize;
        public byte[] Body;

        public Packet(byte[] packet)
        {
            if(packet.Length < 13)
            {
                IsValid = false;
                Console.WriteLine("Dropping packet " + Helpers.ByteArrayToString(packet) + " Invalid length");
                return;
            }

            MemoryStream stream = new MemoryStream(packet);
            this.Type = (PacketType)stream.ReadByte();

            if (!Enum.IsDefined(typeof(PacketType), this.Type))
            {
                IsValid = false;
                Console.WriteLine("Dropping packet " + Helpers.ByteArrayToString(packet) + " Invalid Type");
                return;
            }

            this.Unk = stream.ReadLittleEndianShort();
            this.IsEncrypted = stream.ReadLittleEndianShort();
            this.ID = stream.ReadLittleEndianID();
            this.BodySize = stream.ReadLittleEndianShort();
            if(stream.Length - 13 < BodySize)
            {
                IsValid = false;
                Console.WriteLine("Dropping packet " + Helpers.ByteArrayToString(packet) + " Invalid body size");
                return;
            }

            this.Body = new byte[BodySize];
            stream.Read(this.Body, 0, this.Body.Length);

            stream.Close();
            this.IsValid = true;
        }

        public enum PacketType : byte
        {
            ChangeCipherSpecMessage = 0x14,
            AlertMessage = 0x15,
            HandshakeMessage = 0x16,
            ApplicationDataMessage = 0x17,
            HeartbeatMessage = 0x18
        }

        public override string ToString()
        {
            if (!IsValid)
                return "Invalid packet";
            return " IsValid:" + IsValid + " Type:" + Type.ToString() + " Unk:" + Unk.ToString("X") + " IsEncrypted:" + IsEncrypted + " ID:" + ID.ToString("X") + " BodySize:" + BodySize.ToString("X") + " Body:" + Helpers.ByteArrayToString(Body);
        }
    }
}
