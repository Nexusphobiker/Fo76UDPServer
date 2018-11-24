using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Fo76UDPServer
{
    public class BCrypt
    {
        private IntPtr algHandle = IntPtr.Zero;
        private IntPtr hashHandle = IntPtr.Zero;
        private IntPtr hashSecretBuffAddr;

        public BCrypt()
        {
            //Initialize sha256 and hmac
            if (BCryptOpenAlgorithmProvider(out algHandle, "SHA256", "", 8) != 0)
                throw (new Exception("Failed to open agorithm provider"));
        }

        private BCrypt(IntPtr aHandle, IntPtr hHandle, IntPtr buffAddr)
        {
            this.algHandle = aHandle;
            this.hashHandle = hHandle;
            this.hashSecretBuffAddr = buffAddr;
        }

        public void CreateHash(byte[] Secret)
        {
            hashSecretBuffAddr = Marshal.AllocHGlobal(Secret.Length); //need to dealloc
            Marshal.Copy(Secret, 0, hashSecretBuffAddr, Secret.Length);
            if (BCryptCreateHash(algHandle, out hashHandle, IntPtr.Zero, 0, hashSecretBuffAddr, Secret.Length, 0x20) != 0)
                throw (new Exception("Failed to create hash"));
        }

        //Hell yeah bandaid fixes
        public void CreateHashNoSecretNoHMAC()
        {
            if (BCryptOpenAlgorithmProvider(out algHandle, "SHA256", "", 0) != 0)
                throw (new Exception("Failed to open agorithm provider"));
            if (BCryptCreateHash(algHandle, out hashHandle, IntPtr.Zero, 0, IntPtr.Zero, 0, 0x20) != 0)
                throw (new Exception("Failed to create hash"));
        }

        public void HashData(byte[] data)
        {
            if (hashHandle == IntPtr.Zero)
                throw (new Exception("hashHandle was not initialized"));
            if (BCryptHashData(hashHandle, data, data.Length, 0) != 0)
                throw (new Exception("Failed to hash data"));
        }

        public void FinishHash(byte[] data)
        {
            if (hashHandle == IntPtr.Zero)
                throw (new Exception("hashHandle was not initialized"));
            if (BCryptFinishHash(hashHandle, data, data.Length, 0) != 0)
                throw (new Exception("Failed to finish data"));

        }

        public BCrypt Duplicate()
        {
            if (hashHandle == IntPtr.Zero)
                throw (new Exception("hashHandle was not initialized"));

            IntPtr outHandle = IntPtr.Zero;
            IntPtr keyBuffAddr = Marshal.AllocHGlobal(512); //need to dealloc
            if (BCryptDuplicateHash(this.hashHandle, out outHandle, keyBuffAddr, 512, 0) != 0)
                throw (new Exception("Failed to duplicate hash data"));

            return new BCrypt(this.algHandle, outHandle, keyBuffAddr);
        }

        //https://referencesource.microsoft.com/#system.core/System/Security/Cryptography/BCryptNative.cs

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern int BCryptCreateHash(IntPtr hAlgorithm, [Out] out IntPtr phHash, IntPtr pbHashObject, int cbHashObject, IntPtr pbSecret, int cbSecret, int dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        static extern int BCryptOpenAlgorithmProvider([Out] out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptHashData(IntPtr hHash, [MarshalAs(UnmanagedType.LPArray), In] byte[] pbInput, int cbInput, int dwFlags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptFinishHash(IntPtr hHash, [MarshalAs(UnmanagedType.LPArray), Out] byte[] pbInput, int cbInput, int dwFlags);

        [DllImport("bcrypt.dll")]
        static extern int BCryptDuplicateHash(IntPtr hHash, [Out] out IntPtr phHash, IntPtr pbHashObject, int cbHashObject, int dwFlags);

        [DllImport("Bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint BCryptDecrypt(
                    [In][Out] IntPtr hKey,
                    [In] byte[] pbInput,
                    [In] int cbInput,
                    [In] IntPtr pPaddingInfo,
                    [In] byte[] pbIV,
                    [In] int cbIV,
                    [Out] byte[] pbOutput,
                    [In] int cbOutput,
                    [In] [Out] ref int pcbResult,
                    [In] int dwFlags
                );

        [DllImport("Bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint BCryptGetProperty(
                    [In] IntPtr hObject,
                    [In] String pszProperty,
                    [Out] byte[] pbOutput,
                    [In] int cbOutput,
                    [In] [Out] ref int pcbResult,
                    [In] int dwFlags);

        [DllImport("Bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint BCryptGenerateSymmetricKey(
                   [In]  IntPtr hAlgorithm,
                   [In] [Out] ref IntPtr phKey,
                   [Out] byte[] pbKeyObject,
                   [In] int cbKeyObject,
                   [In] byte[] pbSecret,
                   [In] int cbSecret,
                   [In] int dwFlags
               );

        [DllImport("bcrypt.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint BCryptSetProperty(
                IntPtr hObject,
                string pszProperty,
                string pbInput,
                int cbInput,
                int dwFlags);

        //https://github.com/dotnet/corefx/blob/831dc11b28ef44bb488b10af9d3ad9c86e61b939/src/Common/src/Interop/Windows/BCrypt/Interop.Blobs.cs
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            int cbSize;
            uint dwInfoVersion;
            internal byte* pbNonce;
            internal int cbNonce;
            internal byte* pbAuthData;
            internal int cbAuthData;
            internal byte* pbTag;
            internal int cbTag;
            internal byte* pbMacContext;
            internal int cbMacContext;
            internal int cbAAD;
            internal ulong cbData;
            internal uint dwFlags;

            public static BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Create()
            {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ret = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();

                ret.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);

                const uint BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1;
                ret.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;

                return ret;
            }
        }
    }
}
