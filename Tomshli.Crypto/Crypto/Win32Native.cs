//
// This code was written by Keith Brown, and may be freely used.
// Want to learn more about .NET? Visit pluralsight.com today!
//
using System;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Tomshli.Crypto
{
    internal class Win32Native
    {
        [DllImport("AdvApi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptReleaseContext(IntPtr ctx, int flags);

        [DllImport("AdvApi32.dll", EntryPoint = "CryptAcquireContextW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptAcquireContext(
            out IntPtr providerContext,
            string containerName,
            string providerName,
            int providerType,
            int flags);

        [DllImport("AdvApi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptDestroyKey(IntPtr cryptKeyHandle);

        [DllImport("AdvApi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptGenKey(
            IntPtr providerContext,
            int algorithmId,
            uint flags,
            out IntPtr cryptKeyHandle);

        [DllImport("Crypt32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr CertCreateSelfSignCertificate(
            IntPtr providerHandle,
            [In] CryptoApiBlob subjectIssuerBlob,
            int flags,
            [In] CryptKeyProviderInformation keyProviderInfo,
            IntPtr signatureAlgorithm,
            [In] SystemTime startTime,
            [In] SystemTime endTime,
            IntPtr extensions);

        [DllImport("Crypt32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CertFreeCertificateContext(IntPtr certContext);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FileTimeToSystemTime(
            [In] ref long fileTime,
            [Out] SystemTime systemTime);

        [StructLayout(LayoutKind.Sequential)]
        internal class CryptoApiBlob
        {
            public int DataLength;
            public IntPtr Data;

            public CryptoApiBlob(int dataLength, IntPtr data)
            {
                this.DataLength = dataLength;
                this.Data = data;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class SystemTime
        {
            public short Year;
            public short Month;
            public short DayOfWeek;
            public short Day;
            public short Hour;
            public short Minute;
            public short Second;
            public short Milliseconds;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class CryptKeyProviderInformation
        {
            public string ContainerName;
            public string ProviderName;
            public int ProviderType;
            public int Flags;
            public int ProviderParameterCount;
            public IntPtr ProviderParameters;
            public int KeySpec;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CryptAlgorithmIdentifier
        {
            public String pszObjId;
            public CryptoApiBlob Parameters;
        }

        public static class CryptoAlgorithms
        {
            public static readonly CryptAlgorithmIdentifier Sha256 = new CryptAlgorithmIdentifier
            {
                pszObjId = "1.2.840.113549.1.1.11",
                Parameters = new CryptoApiBlob(0, IntPtr.Zero)
            };        
        }

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpInitialize(
        HTTPAPI_VERSION Version,
        uint Flags,
        IntPtr pReserved);

        [DllImport("httpapi.dll", SetLastError = true)]
        static extern uint HttpSetServiceConfiguration(
             IntPtr ServiceIntPtr,
             HTTP_SERVICE_CONFIG_ID ConfigId,
             IntPtr pConfigInformation,
             int ConfigInformationLength,
             IntPtr pOverlapped);

        [DllImport("httpapi.dll", SetLastError = true)]
        static extern uint HttpDeleteServiceConfiguration(
            IntPtr ServiceIntPtr,
            HTTP_SERVICE_CONFIG_ID ConfigId,
            IntPtr pConfigInformation,
            int ConfigInformationLength,
            IntPtr pOverlapped);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpTerminate(
            uint Flags,
            IntPtr pReserved);

        enum HTTP_SERVICE_CONFIG_ID
        {
            HttpServiceConfigIPListenList = 0,
            HttpServiceConfigSSLCertInfo,
            HttpServiceConfigUrlAclInfo,
            HttpServiceConfigMax
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_IP_LISTEN_PARAM
        {
            public ushort AddrLength;
            public IntPtr pAddress;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct HTTP_SERVICE_CONFIG_SSL_SET
        {
            public HTTP_SERVICE_CONFIG_SSL_KEY KeyDesc;
            public HTTP_SERVICE_CONFIG_SSL_PARAM ParamDesc;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_SERVICE_CONFIG_SSL_KEY
        {
            public IntPtr pIpPort;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct HTTP_SERVICE_CONFIG_SSL_PARAM
        {
            public int SslHashLength;
            public IntPtr pSslHash;
            public Guid AppId;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pSslCertStoreName;
            public uint DefaultCertCheckMode;
            public int DefaultRevocationFreshnessTime;
            public int DefaultRevocationUrlRetrievalTimeout;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pDefaultSslCtlIdentifier;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pDefaultSslCtlStoreName;
            public uint DefaultFlags;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        public struct HTTPAPI_VERSION
        {
            public ushort HttpApiMajorVersion;
            public ushort HttpApiMinorVersion;

            public HTTPAPI_VERSION(ushort majorVersion, ushort minorVersion)
            {
                HttpApiMajorVersion = majorVersion;
                HttpApiMinorVersion = minorVersion;
            }
        }

        public const uint HTTP_INITIALIZE_CONFIG = 0x00000002;
        public const uint HTTP_SERVICE_CONFIG_SSL_FLAG_USE_DS_MAPPER = 0x00000001;
        public const uint HTTP_SERVICE_CONFIG_SSL_FLAG_NEGOTIATE_CLIENT_CERT = 0x00000002;
        public const uint HTTP_SERVICE_CONFIG_SSL_FLAG_NO_RAW_FILTER = 0x00000004;
        private static int NOERROR = 0;
        private static int ERROR_ALREADY_EXISTS = 183;

        public static void BindCertificate(string ipAddress, int port, byte[] hash)
        {
            uint retVal = (uint)NOERROR; // NOERROR = 0

            HTTPAPI_VERSION httpApiVersion = new HTTPAPI_VERSION(1, 0);
            retVal = HttpInitialize(httpApiVersion, HTTP_INITIALIZE_CONFIG, IntPtr.Zero);
            if ((uint)NOERROR == retVal)
            {
                HTTP_SERVICE_CONFIG_SSL_SET configSslSet = new HTTP_SERVICE_CONFIG_SSL_SET();
                HTTP_SERVICE_CONFIG_SSL_KEY httpServiceConfigSslKey = new HTTP_SERVICE_CONFIG_SSL_KEY();
                HTTP_SERVICE_CONFIG_SSL_PARAM configSslParam = new HTTP_SERVICE_CONFIG_SSL_PARAM();

                IPAddress ip = IPAddress.Parse(ipAddress);

                IPEndPoint ipEndPoint = new IPEndPoint(ip, port);
                // serialize the endpoint to a SocketAddress and create an array to hold the values.  Pin the array.
                SocketAddress socketAddress = ipEndPoint.Serialize();
                byte[] socketBytes = new byte[socketAddress.Size];
                GCHandle handleSocketAddress = GCHandle.Alloc(socketBytes, GCHandleType.Pinned);
                // Should copy the first 16 bytes (the SocketAddress has a 32 byte buffer, the size will only be 16,
                //which is what the SOCKADDR accepts
                for (int i = 0; i < socketAddress.Size; ++i)
                {
                    socketBytes[i] = socketAddress[i];
                }

                httpServiceConfigSslKey.pIpPort = handleSocketAddress.AddrOfPinnedObject();

                GCHandle handleHash = GCHandle.Alloc(hash, GCHandleType.Pinned);
                configSslParam.AppId = Guid.NewGuid();
                configSslParam.DefaultCertCheckMode = 0;
                configSslParam.DefaultFlags = HTTP_SERVICE_CONFIG_SSL_FLAG_NEGOTIATE_CLIENT_CERT;
                configSslParam.DefaultRevocationFreshnessTime = 0;
                configSslParam.DefaultRevocationUrlRetrievalTimeout = 0;
                configSslParam.pSslCertStoreName = StoreName.My.ToString();
                configSslParam.pSslHash = handleHash.AddrOfPinnedObject();
                configSslParam.SslHashLength = hash.Length;
                configSslSet.ParamDesc = configSslParam;
                configSslSet.KeyDesc = httpServiceConfigSslKey;

                IntPtr pInputConfigInfo = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(HTTP_SERVICE_CONFIG_SSL_SET)));
                Marshal.StructureToPtr(configSslSet, pInputConfigInfo, false);

                retVal = HttpSetServiceConfiguration(IntPtr.Zero,
                    HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                    pInputConfigInfo,
                    Marshal.SizeOf(configSslSet),
                    IntPtr.Zero);

                if ((uint)ERROR_ALREADY_EXISTS == retVal)  // ERROR_ALREADY_EXISTS = 183
                {
                    retVal = HttpDeleteServiceConfiguration(IntPtr.Zero,
                    HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                    pInputConfigInfo,
                    Marshal.SizeOf(configSslSet),
                    IntPtr.Zero);

                    if ((uint)NOERROR == retVal)
                    {
                        retVal = HttpSetServiceConfiguration(IntPtr.Zero,
                            HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                            pInputConfigInfo,
                            Marshal.SizeOf(configSslSet),
                            IntPtr.Zero);
                    }
                }

                handleSocketAddress.Free();
                handleHash.Free();
                Marshal.FreeCoTaskMem(pInputConfigInfo);
                HttpTerminate(HTTP_INITIALIZE_CONFIG, IntPtr.Zero);
            }

            if ((uint)NOERROR != retVal)
            {
                throw new Win32Exception(Convert.ToInt32(retVal));
            }
        }
    }
}
