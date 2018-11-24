using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Fo76UDPServer
{
    public class DotNetUDP
    {
        private static List<Client> ConnectedClients = new List<Client>();
        private Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private const int BufferSize = 8192;
        private byte[] PacketBuffer = new byte[BufferSize];
        private EndPoint ClientEndpoint = new IPEndPoint(IPAddress.Any, 0);
        private AsyncCallback AsReceive = null;
        private AsyncBuffer AsBuffer = new AsyncBuffer();

        public void Start(string addr,int port)
        {
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.ReuseAddress, true);
            socket.Bind(new IPEndPoint(IPAddress.Parse(addr), port));
            Receive();
        }

        public void Kill()
        {
            socket.Close();
        }

        //first recieve fails not sure why
        private void Receive()
        {
            socket.BeginReceiveFrom(PacketBuffer, 0, BufferSize, SocketFlags.None, ref ClientEndpoint, AsReceive = (ar) =>
            {
                AsyncBuffer so = (AsyncBuffer)ar.AsyncState;
                int bytes = socket.EndReceiveFrom(ar, ref ClientEndpoint);
                socket.BeginReceiveFrom(so.Buffer, 0, BufferSize, SocketFlags.None, ref ClientEndpoint, AsReceive, so);
                byte[] tempBuff = new byte[bytes];
                Array.Copy(so.Buffer, 0, tempBuff, 0, tempBuff.Length);

                Client TargetClient = null;
                //Check if client is already connected
                if(ConnectedClients.Where(x => x.endPoint.Equals(ClientEndpoint)).Count() == 0)
                {
                    Console.WriteLine("New client connected " + ClientEndpoint.ToString());
                    TargetClient = new Client(ClientEndpoint);
                    ConnectedClients.Add(TargetClient);
                }
                else
                {
                    TargetClient = ConnectedClients.Where(x => x.endPoint.Equals(ClientEndpoint)).First();
                }

                Packet packet = new Packet(tempBuff);
                if (packet.IsValid)
                {
                    Console.WriteLine("Recieved " + packet.ToString());
                    socket.SendTo(TargetClient.HandlePacket(packet), ClientEndpoint);
                }
            }, AsBuffer);
        }

        private class AsyncBuffer
        {
            public byte[] Buffer = new byte[BufferSize];
        }
    }
}
