using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Fo76UDPServer.Messages;

namespace Fo76UDPServer
{
    class Client
    {
        public EndPoint endPoint;

        private bool AreRandomsSet = false;
        private byte[] ClientRandom = new byte[0x20];
        private byte[] ServerRandom = new byte[0x20];

        private bool IsServerSecretSet = false;

        private byte[] ServerSecret = new byte[0x20];

        private byte[] ClientSecret = new byte[0x12];

        private Crypt CryptHandle;

        private Crypt.IdentificationHash IDHash = new Crypt.IdentificationHash();

        public Client(EndPoint endPoint)
        {
            this.endPoint = endPoint;
        }

        public byte[] HandlePacket(Packet packet)
        {
            switch (packet.Type)
            {
                case Packet.PacketType.AlertMessage:
                    return HandleAlertMessage(packet);
                case Packet.PacketType.ApplicationDataMessage:
                    throw (new Exception("not implemented"));
                case Packet.PacketType.ChangeCipherSpecMessage:
                    return HandleChangeCipherSpecMessage(packet);
                case Packet.PacketType.HandshakeMessage:
                    return HandleHandshakeMessage(packet);
                case Packet.PacketType.HeartbeatMessage:
                    throw (new Exception("not implemented"));
                default:
                    throw (new Exception("Invalid message recieved"));
            }
        }

        private byte[] HandleChangeCipherSpecMessage(Packet packet)
        {
            ChangeCipherSpecMessage msg = new ChangeCipherSpecMessage(packet.Body);
            Console.WriteLine("[HandleChangeCipherSpecMessage] " + msg.ToString());
            return ChangeCipherSpecMessage.BuildChangeCipherSpecMessageResponse();
        }

        private byte[] HandleHandshakeMessage(Packet packet)
        {
            HandshakeMessage msg = new HandshakeMessage(packet.Body);
            Console.WriteLine("[HandleHandshakeMessage] "+msg.ToString());

            switch (msg.MessageType)
            {
                case HandshakeMessage.HandshakeMessageType.Certificate:
                    throw (new Exception("not implemented"));
                case HandshakeMessage.HandshakeMessageType.CertificateRequest:
                    throw (new Exception("not implemented"));
                case HandshakeMessage.HandshakeMessageType.CertificateVerify:
                    throw (new Exception("not implemented"));
                case HandshakeMessage.HandshakeMessageType.ClientHello:
                    if (!AreRandomsSet)
                    {
                        Array.Copy(msg.Data, 2, ClientRandom, 0, ClientRandom.Length); //Save client random and respond with HelloVerifyRequest
                        ServerSecret = Helpers.GenRandomBytes(0x20);
                        AreRandomsSet = true;
                        return HandshakeMessage.BuildHelloVerifyResponse(ServerSecret);
                    }
                    else
                    {
                        //Just because of the hashing. the entire structure needs to be rebuild really really badly
                        Array.Copy(packet.Body, 0, IDHash.SecondClientHelloHeader, 0, IDHash.SecondClientHelloHeader.Length);
                        Array.Copy(packet.Body, 0xC, IDHash.SecondClientHelloData, 0, IDHash.SecondClientHelloData.Length);

                        ServerRandom = Helpers.GenRandomBytes(0x20);
                        byte[] fillIn = { 0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x5D, 0x02, 0x00, 0x00, 0x2D, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2D, 0xFE, 0xFD, 0x6A, 0x46, 0x4E, 0xDF, 0xC8, 0xE0, 0x45, 0x96, 0x0C, 0x90, 0x1D, 0xC1, 0xF4, 0xC2, 0x90, 0x37, 0x87, 0xC8, 0x39, 0x95, 0x44, 0x7B, 0x2B, 0xE7, 0x87, 0x9D, 0xE4, 0xF7, 0x8E, 0x25, 0x91, 0xE1, 0x00, 0x00, 0xA8, 0x00, 0x00, 0x05, 0xFF, 0x01, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x0C, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x0A, 0x50, 0x52, 0x4F, 0x4A, 0x45, 0x43, 0x54, 0x5F, 0x37, 0x36, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                        Array.Copy(ServerRandom, 0, fillIn, 0x1B, ServerRandom.Length);

                        Array.Copy(fillIn, 0xD, IDHash.ServerHelloResponseHeader, 0, IDHash.ServerHelloResponseHeader.Length);
                        Array.Copy(fillIn, 0x19, IDHash.ServerHelloResponseData, 0, IDHash.ServerHelloResponseData.Length);
                        Array.Copy(fillIn, 0x46, IDHash.ServerHelloResponseSecondPartHeader, 0, IDHash.ServerHelloResponseSecondPartHeader.Length);
                        Array.Copy(fillIn, 0x52, IDHash.ServerHelloResponseSecondPartData, 0, IDHash.ServerHelloResponseSecondPartData.Length);
                        Array.Copy(fillIn, 0x5E, IDHash.ServerHelloResponseSecondPartTail, 0, IDHash.ServerHelloResponseSecondPartTail.Length);
                        Console.WriteLine("WROTE ID");
                        
                        IsServerSecretSet = true;
                        return HandshakeMessage.BuildServerHelloResponse(ServerRandom);
                    }
                case HandshakeMessage.HandshakeMessageType.ClientKeyExchange:
                    Array.Copy(msg.Data, 2, ClientSecret, 0, ClientSecret.Length);

                    Array.Copy(packet.Body,0,  IDHash.ClientKeyExchangeHeader,0,IDHash.ClientKeyExchangeHeader.Length);
                    Array.Copy(packet.Body, 0xC, IDHash.ClientKeyExchangeData, 0, IDHash.ClientKeyExchangeData.Length);
                    return new byte[] { };
                case HandshakeMessage.HandshakeMessageType.Finished:
                    throw (new Exception("not implemented"));
                case HandshakeMessage.HandshakeMessageType.HelloRequest:
                    CryptHandle = new Crypt(ClientRandom, ServerRandom);
                    byte[] EncryptedData = new byte[0x18];
                    Array.Copy(packet.Body, 8, EncryptedData, 0, 0x18);
                    Console.WriteLine("EncryptedData:"+Helpers.ByteArrayToString(EncryptedData));
                    byte[] Tag = new byte[0x10];
                    Array.Copy(packet.Body, 32, Tag, 0, Tag.Length);
                    Console.WriteLine("Tag:" + Helpers.ByteArrayToString(Tag));
                    byte[] decryptedData = CryptHandle.Decrypt(EncryptedData, Tag, new byte[] { (byte)packet.Type, BitConverter.GetBytes(packet.Unk)[1], BitConverter.GetBytes(packet.Unk)[0] }, packet.ID);
                    Console.WriteLine("Decrypted Data:"+Helpers.ByteArrayToString(decryptedData));

                    Array.Copy(decryptedData, 0, IDHash.EncryptedHashMessageHeader, 0, IDHash.EncryptedHashMessageHeader.Length);
                    Array.Copy(decryptedData, 0xC, IDHash.EncryptedHashMessageData, 0, IDHash.EncryptedHashMessageData.Length);

                    Console.WriteLine("IDHASH:" + IDHash.ToString());
                    byte[] msgHash = CryptHandle.GenerateIdentificationHash(IDHash);
                    Console.WriteLine("msgHash:" + Helpers.ByteArrayToString(msgHash));

                    return HandshakeMessage.BuildHelloRequestResponse(CryptHandle,msgHash);
                case HandshakeMessage.HandshakeMessageType.HelloVerifyRequest:
                    throw (new Exception("not implemented"));
                case HandshakeMessage.HandshakeMessageType.ServerHello:
                    throw (new Exception("not implemented"));
                case HandshakeMessage.HandshakeMessageType.ServerHelloDone:
                    throw (new Exception("not implemented"));
                case HandshakeMessage.HandshakeMessageType.ServerKeyExchange:
                    throw (new Exception("not implemented"));
                default:
                    throw (new Exception("Invalid MessageType"));
            }
        }

        private byte[] HandleAlertMessage(Packet packet)
        {
            AlertMessage msg = new AlertMessage(packet.Body);
            Console.WriteLine("[HandleAlertMessage] " + msg.ToString());
            return new byte[] { };
        }
    }
}
