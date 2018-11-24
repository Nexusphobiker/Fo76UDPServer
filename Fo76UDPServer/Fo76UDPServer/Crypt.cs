using Security.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Fo76UDPServer
{
    class Crypt
    {
        //TODO: clean up and change to a .net implementation of sha256
        //public IdentificationHash IDHash = new IdentificationHash();

        private byte[] HashSecretServerPassword = new byte[] { 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A };
        private byte[] DecryptionKey = new byte[16];
        private byte[] EncryptionKey = new byte[16];
        private byte[] DecryptNonceHash = new byte[4];
        private byte[] EncryptNonceHash = new byte[4];
        private byte[] hashSecret = new byte[48];

        public Crypt(byte[] ClientRandom, byte[] ServerRandom)
        {

            BCrypt bCrypt = new BCrypt();
            bCrypt.CreateHash(HashSecretServerPassword);
            byte[] masterSecretBuff = Encoding.Default.GetBytes("master secret");
            bCrypt.HashData(masterSecretBuff);
            byte[] BothRandomBuff = new byte[64];
            Array.Copy(ClientRandom, BothRandomBuff, 32);
            Array.Copy(ServerRandom, 0, BothRandomBuff, 32, 32);
            bCrypt.HashData(BothRandomBuff);
            byte[] outputBuff = new byte[32];
            bCrypt.FinishHash(outputBuff);
            bCrypt.HashData(outputBuff);
            BCrypt secondBCryptHashHandle = bCrypt.Duplicate();
            bCrypt.FinishHash(outputBuff);

            secondBCryptHashHandle.HashData(masterSecretBuff);
            secondBCryptHashHandle.HashData(BothRandomBuff);
            byte[] secondOutputBuff = new byte[32];
            secondBCryptHashHandle.FinishHash(secondOutputBuff);
            Array.Copy(secondOutputBuff, hashSecret, secondOutputBuff.Length); //hashsecret part 1

            bCrypt.HashData(outputBuff);
            secondBCryptHashHandle = bCrypt.Duplicate();
            bCrypt.FinishHash(outputBuff);
            secondBCryptHashHandle.HashData(masterSecretBuff);
            secondBCryptHashHandle.HashData(BothRandomBuff);
            secondBCryptHashHandle.FinishHash(secondOutputBuff);
            Array.Copy(secondOutputBuff, 0, hashSecret, 32, 16); //hashsecret part 2

            bCrypt = new BCrypt();
            bCrypt.CreateHash(hashSecret);
            byte[] keyExpansionBuff = Encoding.Default.GetBytes("key expansion");
            bCrypt.HashData(keyExpansionBuff);
            byte[] BothRandomReversedBuff = new byte[64];
            Array.Copy(ServerRandom, BothRandomReversedBuff, 32);
            Array.Copy(ClientRandom, 0, BothRandomReversedBuff, 32, 32);
            bCrypt.HashData(BothRandomReversedBuff);
            bCrypt.FinishHash(outputBuff);

            bCrypt.HashData(outputBuff);
            secondBCryptHashHandle = bCrypt.Duplicate();
            bCrypt.FinishHash(outputBuff);
            secondBCryptHashHandle.HashData(keyExpansionBuff);
            secondBCryptHashHandle.HashData(BothRandomReversedBuff);
            secondBCryptHashHandle.FinishHash(secondOutputBuff);

            Array.Copy(secondOutputBuff, 0, DecryptionKey, 0, 16);
            Array.Copy(secondOutputBuff, 16, EncryptionKey, 0, 16);

            bCrypt.HashData(outputBuff);
            secondBCryptHashHandle = bCrypt.Duplicate();
            bCrypt.FinishHash(outputBuff);

            secondBCryptHashHandle.HashData(keyExpansionBuff);
            secondBCryptHashHandle.HashData(BothRandomReversedBuff);
            secondBCryptHashHandle.FinishHash(secondOutputBuff);


            Array.Copy(secondOutputBuff, 0, DecryptNonceHash, 0, 4);
            Array.Copy(secondOutputBuff, 4, EncryptNonceHash, 0, 4);
            Console.WriteLine("DecryptNonceHash:" + Helpers.ByteArrayToString(DecryptNonceHash));
            Console.WriteLine("EncryptNonceHash:" + Helpers.ByteArrayToString(EncryptNonceHash));
        }

        public byte[] Encrypt(byte[] Plain,out byte[] Tag, byte[] PacketHead, long PacketID)
        {
            byte[] RetVar;
            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.Key = EncryptionKey;

                //------------- Build Nonce ------------- 
                byte[] nonce = new byte[12];
                Array.Copy(EncryptNonceHash, nonce, 4);
                //Encryption flag probably
                Array.Copy(new byte[] { 0x00, 0x01 }, 0, nonce, 4, 2);
                //Little Endian Packet ID to be send
                //Array.Copy(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 0, nonce, 6, 6);
                Array.Copy(BitConverter.GetBytes(PacketID).Reverse().ToArray(), 2, nonce, 6, 6);
                Console.WriteLine("nonce:" + Helpers.ByteArrayToString(nonce));
                aes.IV = nonce;

                //------------- Build Associated Data ------------- 
                byte[] associatedData = new byte[13]; // { 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0xFE, 0xFD, 0x00, 0x18 };
                //Encryption flag probably
                Array.Copy(new byte[] { 0x00, 0x01 }, associatedData, 2);
                //Little Endian Packet ID to be send
                Array.Copy(BitConverter.GetBytes(PacketID).Reverse().ToArray(), 2, associatedData, 2, 6);
                //Packet header
                //Array.Copy(new byte[] { 0x16, 0xFE, 0xFD }, 0, associatedData, 8, 3);
                Array.Copy(PacketHead, 0, associatedData, 8, 3);
                //data length
                short EncryptedDataLen = (short)Plain.Length;
                Array.Copy(BitConverter.GetBytes(EncryptedDataLen).Reverse().ToArray(), 0, associatedData, 11, 2);
                //Array.Copy(new byte[] { 0x00, 0x18 }, 0, associatedData, 11, 2);
                Console.WriteLine("associatedData:" + Helpers.ByteArrayToString(associatedData));

                aes.AuthenticatedData = associatedData;

                using (MemoryStream ms = new MemoryStream())

                using (var encryptor = aes.CreateAuthenticatedEncryptor())

                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))

                {
                    cs.Write(Plain, 0, Plain.Length);
                    cs.FlushFinalBlock();
                    RetVar = ms.ToArray();
                    Tag = encryptor.GetTag();
                }

            }

            return RetVar;
        }

        public byte[] Decrypt(byte[] EncryptedData, byte[] Tag, byte[] PacketHead, long PacketID)
        {
            byte[] RetVar;
            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;
                aes.Key = DecryptionKey;

                //------------- Build Nonce ------------- 
                byte[] nonce = new byte[12];
                Array.Copy(DecryptNonceHash, nonce, 4);
                //Encryption flag probably
                Array.Copy(new byte[] { 0x00, 0x01 }, 0, nonce, 4, 2);
                //Little Endian Packet ID to be send
                //Array.Copy(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 0, nonce, 6, 6);
                Array.Copy(BitConverter.GetBytes(PacketID).Reverse().ToArray(), 2, nonce, 6, 6);

                aes.IV = nonce;

                //------------- Build Associated Data ------------- 
                byte[] associatedData = new byte[13]; // { 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0xFE, 0xFD, 0x00, 0x18 };
                //Encryption flag probably
                Array.Copy(new byte[] { 0x00, 0x01 }, associatedData, 2);
                //Little Endian Packet ID to be send
                Array.Copy(BitConverter.GetBytes(PacketID).Reverse().ToArray(), 2, associatedData, 2, 6);
                //Packet header
                //Array.Copy(new byte[] { 0x16, 0xFE, 0xFD }, 0, associatedData, 8, 3);
                Array.Copy(PacketHead, 0, associatedData, 8, 3);
                //data length
                short EncryptedDataLen = (short)EncryptedData.Length;
                Array.Copy(BitConverter.GetBytes(EncryptedDataLen).Reverse().ToArray(), 0, associatedData, 11, 2);
                //Array.Copy(new byte[] { 0x00, 0x18 }, 0, associatedData, 11, 2);

                aes.AuthenticatedData = associatedData;

                aes.Tag = Tag;

                using (MemoryStream ms = new MemoryStream())

                using (var decryptor = aes.CreateDecryptor())

                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))

                {
                    cs.Write(EncryptedData, 0, EncryptedData.Length);
                    cs.FlushFinalBlock();
                    RetVar = ms.ToArray();
                }

            }

            return RetVar;
        }

        public byte[] GenerateIdentificationHash(IdentificationHash IDHash)
        {
            BCrypt bCrypt = new BCrypt();
            bCrypt.CreateHashNoSecretNoHMAC();
            bCrypt.HashData(IDHash.SecondClientHelloHeader);
            bCrypt.HashData(IDHash.SecondClientHelloData);
            bCrypt.HashData(IDHash.ServerHelloResponseHeader);
            bCrypt.HashData(IDHash.ServerHelloResponseData);
            bCrypt.HashData(IDHash.ServerHelloResponseSecondPartHeader);
            bCrypt.HashData(IDHash.ServerHelloResponseSecondPartData);
            bCrypt.HashData(IDHash.ServerHelloResponseSecondPartTail);
            //bCrypt.HashData(new byte[] { });
            bCrypt.HashData(IDHash.ClientKeyExchangeHeader);
            bCrypt.HashData(IDHash.ClientKeyExchangeData);
            bCrypt.HashData(IDHash.EncryptedHashMessageHeader);
            bCrypt.HashData(IDHash.EncryptedHashMessageData);
            byte[] outputBuff = new byte[32];
            bCrypt.FinishHash(outputBuff);

            BCrypt secondBCrypt = new BCrypt();
            byte[] secondOutputBuff = new byte[32];
            
            secondBCrypt.CreateHash(this.hashSecret);
            secondBCrypt.HashData(Encoding.Default.GetBytes("server finished"));
            secondBCrypt.HashData(outputBuff);
            secondBCrypt.FinishHash(secondOutputBuff);

            secondBCrypt.HashData(secondOutputBuff);
            bCrypt = secondBCrypt.Duplicate();

            bCrypt.HashData(Encoding.Default.GetBytes("server finished"));
            bCrypt.HashData(outputBuff);

            bCrypt.FinishHash(secondOutputBuff);

            byte[] retVar = new byte[0xC];
            Array.Copy(secondOutputBuff, 0, retVar, 0, retVar.Length);
            return retVar;
        }

        public class IdentificationHash
        {
            public byte[] SecondClientHelloHeader = new byte[0xC];
            public byte[] SecondClientHelloData = new byte[0x5B];
            public byte[] ServerHelloResponseHeader = new byte[0xC];
            public byte[] ServerHelloResponseData = new byte[0x2D];
            public byte[] ServerHelloResponseSecondPartHeader = new byte[0xC];
            public byte[] ServerHelloResponseSecondPartData = new byte[0xC]; //PROJECT_76
            public byte[] ServerHelloResponseSecondPartTail = new byte[0xC];
            public byte[] ClientKeyExchangeHeader = new byte[0xC];
            public byte[] ClientKeyExchangeData = new byte[0x14]; //Client generated string 88xxxxx...
            public byte[] EncryptedHashMessageHeader = new byte[0xC];
            public byte[] EncryptedHashMessageData = new byte[0xC];

            public override string ToString()
            {
                return " SecondClientHelloHeader:" + Helpers.ByteArrayToString(SecondClientHelloHeader) + "\n" +
                       " SecondClientHelloData:" + Helpers.ByteArrayToString(SecondClientHelloData) + "\n" +
                       " ServerHelloResponseHeader:" + Helpers.ByteArrayToString(ServerHelloResponseHeader) + "\n" +
                       " ServerHelloResponseData:" + Helpers.ByteArrayToString(ServerHelloResponseData) + "\n" +
                       " ServerHelloResponseSecondPartHeader:" + Helpers.ByteArrayToString(ServerHelloResponseSecondPartHeader) + "\n" +
                       " ServerHelloResponseSecondPartData:" + Helpers.ByteArrayToString(ServerHelloResponseSecondPartData) + "\n" +
                       " ServerHelloResponseSecondPartTail:" + Helpers.ByteArrayToString(ServerHelloResponseSecondPartTail) + "\n" +
                       " ClientKeyExchangeHeader:" + Helpers.ByteArrayToString(ClientKeyExchangeHeader) + "\n" +
                       " ClientKeyExchangeData:" + Helpers.ByteArrayToString(ClientKeyExchangeData) + "\n" +
                       " EncryptedHashMessageHeader:" + Helpers.ByteArrayToString(EncryptedHashMessageHeader) + "\n" +
                       " EncryptedHashMessageData:" + Helpers.ByteArrayToString(EncryptedHashMessageData);
            }
        }

    }
}
