/*
Author: Arno0x0x, Twitter: @Arno0x0x

How to compile:
===============
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /unsafe /out:dnsResolver.dll dnsResolver.cs

*/
using System;
using System.Net;
using System.Collections;
using System.ComponentModel;
using System.Runtime.InteropServices;
	
namespace DNSDelivery
{
	//============================================================================================
	// This class provides DNS resolution by using the PInvoke calls to the native Win32 API
	//============================================================================================
    public class DnsResolver
    {       
		//---------------------------------------------------------------------------------
		// Import WIN32 API extern function
		//---------------------------------------------------------------------------------
        [DllImport("dnsapi", EntryPoint="DnsQuery_W", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
        private static extern int DnsQuery([MarshalAs(UnmanagedType.VBByRefStr)]ref string pszName, DnsRecordTypes wType, DnsQueryOptions options, ref IP4_ARRAY dnsServerIpArray, ref IntPtr ppQueryResults, int pReserved);

        [DllImport("dnsapi", CharSet=CharSet.Auto, SetLastError=true)]
        private static extern void DnsRecordListFree(IntPtr pRecordList, int FreeType);

		//---------------------------------------------------------------------------------
		// Resolving TXT records only for now
		//---------------------------------------------------------------------------------
        public static string[] GetTXTRecords(string domain, string serverIP = null)
        {
			IntPtr recordsArray = IntPtr.Zero;
			IntPtr dnsRecord = IntPtr.Zero;
            TXTRecord txtRecord;
			IP4_ARRAY dnsServerArray = new IP4_ARRAY();
			
			if (serverIP != null) {
				uint address = BitConverter.ToUInt32(IPAddress.Parse(serverIP).GetAddressBytes(), 0);
				uint[] ipArray = new uint[1];
				ipArray.SetValue(address, 0);
				dnsServerArray.AddrCount = 1;
				dnsServerArray.AddrArray = new uint[1];
				dnsServerArray.AddrArray[0] = address;
			}
			
           
			// Interop calls will only work on Windows platform (no mono c#)
			if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new NotSupportedException();
            }
			
			ArrayList recordList = new ArrayList();
			try
			{
				int queryResult = DnsResolver.DnsQuery(ref domain, DnsRecordTypes.DNS_TYPE_TXT, DnsQueryOptions.DNS_QUERY_BYPASS_CACHE, ref dnsServerArray, ref recordsArray, 0);
				
				// Check for error
				if (queryResult != 0)
				{
					throw new Win32Exception(queryResult);
				}
				
				// Loop through the result record list
				for (dnsRecord = recordsArray; !dnsRecord.Equals(IntPtr.Zero); dnsRecord = txtRecord.pNext)
				{
					txtRecord = (TXTRecord) Marshal.PtrToStructure(dnsRecord, typeof(TXTRecord));
					if (txtRecord.wType == (int)DnsRecordTypes.DNS_TYPE_TXT)
					{
						//Console.WriteLine("Size of array: {0}",txtRecord.dwStringCount);
						string txt = Marshal.PtrToStringAuto(txtRecord.pStringArray);
						recordList.Add(txt);
					}
				}
			}
			finally
			{
				DnsResolver.DnsRecordListFree(recordsArray, 0);
			}
				return (string[]) recordList.ToArray(typeof(string));
		}

		//---------------------------------------------------------------------------------
		// WIN32 DNS STRUCTURES
		//---------------------------------------------------------------------------------
		/// <summary>
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms682139(v=vs.85).aspx
		/// </summary>
		public struct IP4_ARRAY
		{
			/// DWORD->unsigned int
			public UInt32 AddrCount;
			/// IP4_ADDRESS[1]
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.U4)] public UInt32[] AddrArray;
		}
		
		/// <summary>
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms682082(v=vs.85).aspx
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
        private struct MXRecord
        {
			// Generic DNS record structure
            public IntPtr pNext;
            public string pName;
            public short wType;
            public short wDataLength;
            public int flags;
            public int dwTtl;
            public int dwReserved;
            
			// MX record specific
			public IntPtr pNameExchange;
            public short wPreference;
            public short Pad;
        }
		
		[StructLayout(LayoutKind.Sequential)]
        private struct TXTRecord
        {
			// Generic DNS record structure
            public IntPtr pNext;
            public string pName;
            public short wType;
            public short wDataLength;
            public int flags;
            public int dwTtl;
            public int dwReserved;
            
			// MX record specific
			public int dwStringCount;
            public IntPtr pStringArray;
            
        }
		
		/// <summary>
		/// See http://msdn.microsoft.com/en-us/library/windows/desktop/cc982162(v=vs.85).aspx
		/// </summary>
		[Flags]
		private enum DnsQueryOptions
		{
			DNS_QUERY_STANDARD = 0x0,
			DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 0x1,
			DNS_QUERY_USE_TCP_ONLY = 0x2,
			DNS_QUERY_NO_RECURSION = 0x4,
			DNS_QUERY_BYPASS_CACHE = 0x8,
			DNS_QUERY_NO_WIRE_QUERY = 0x10,
			DNS_QUERY_NO_LOCAL_NAME = 0x20,
			DNS_QUERY_NO_HOSTS_FILE = 0x40,
			DNS_QUERY_NO_NETBT = 0x80,
			DNS_QUERY_WIRE_ONLY = 0x100,
			DNS_QUERY_RETURN_MESSAGE = 0x200,
			DNS_QUERY_MULTICAST_ONLY = 0x400,
			DNS_QUERY_NO_MULTICAST = 0x800,
			DNS_QUERY_TREAT_AS_FQDN = 0x1000,
			DNS_QUERY_ADDRCONFIG = 0x2000,
			DNS_QUERY_DUAL_ADDR = 0x4000,
			DNS_QUERY_MULTICAST_WAIT = 0x20000,
			DNS_QUERY_MULTICAST_VERIFY = 0x40000,
			DNS_QUERY_DONT_RESET_TTL_VALUES = 0x100000,
			DNS_QUERY_DISABLE_IDN_ENCODING = 0x200000,
			DNS_QUERY_APPEND_MULTILABEL = 0x800000,
			DNS_QUERY_RESERVED = unchecked((int)0xF0000000)
		}

		/// <summary>
		/// See http://msdn.microsoft.com/en-us/library/windows/desktop/cc982162(v=vs.85).aspx
		/// Also see http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
		/// </summary>
		private enum DnsRecordTypes
		{
			DNS_TYPE_A = 0x1,
			DNS_TYPE_NS = 0x2,
			DNS_TYPE_MD = 0x3,
			DNS_TYPE_MF = 0x4,
			DNS_TYPE_CNAME = 0x5,
			DNS_TYPE_SOA = 0x6,
			DNS_TYPE_MB = 0x7,
			DNS_TYPE_MG = 0x8,
			DNS_TYPE_MR = 0x9,
			DNS_TYPE_NULL = 0xA,
			DNS_TYPE_WKS = 0xB,
			DNS_TYPE_PTR = 0xC,
			DNS_TYPE_HINFO = 0xD,
			DNS_TYPE_MINFO = 0xE,
			DNS_TYPE_MX = 0xF,
			DNS_TYPE_TEXT = 0x10,       // This is how it's specified on MSDN
			DNS_TYPE_TXT = DNS_TYPE_TEXT,
			DNS_TYPE_RP = 0x11,
			DNS_TYPE_AFSDB = 0x12,
			DNS_TYPE_X25 = 0x13,
			DNS_TYPE_ISDN = 0x14,
			DNS_TYPE_RT = 0x15,
			DNS_TYPE_NSAP = 0x16,
			DNS_TYPE_NSAPPTR = 0x17,
			DNS_TYPE_SIG = 0x18,
			DNS_TYPE_KEY = 0x19,
			DNS_TYPE_PX = 0x1A,
			DNS_TYPE_GPOS = 0x1B,
			DNS_TYPE_AAAA = 0x1C,
			DNS_TYPE_LOC = 0x1D,
			DNS_TYPE_NXT = 0x1E,
			DNS_TYPE_EID = 0x1F,
			DNS_TYPE_NIMLOC = 0x20,
			DNS_TYPE_SRV = 0x21,
			DNS_TYPE_ATMA = 0x22,
			DNS_TYPE_NAPTR = 0x23,
			DNS_TYPE_KX = 0x24,
			DNS_TYPE_CERT = 0x25,
			DNS_TYPE_A6 = 0x26,
			DNS_TYPE_DNAME = 0x27,
			DNS_TYPE_SINK = 0x28,
			DNS_TYPE_OPT = 0x29,
			DNS_TYPE_DS = 0x2B,
			DNS_TYPE_RRSIG = 0x2E,
			DNS_TYPE_NSEC = 0x2F,
			DNS_TYPE_DNSKEY = 0x30,
			DNS_TYPE_DHCID = 0x31,
			DNS_TYPE_UINFO = 0x64,
			DNS_TYPE_UID = 0x65,
			DNS_TYPE_GID = 0x66,
			DNS_TYPE_UNSPEC = 0x67,
			DNS_TYPE_ADDRS = 0xF8,
			DNS_TYPE_TKEY = 0xF9,
			DNS_TYPE_TSIG = 0xFA,
			DNS_TYPE_IXFR = 0xFB,
			DNS_TYPE_AFXR = 0xFC,
			DNS_TYPE_MAILB = 0xFD,
			DNS_TYPE_MAILA = 0xFE,
			DNS_TYPE_ALL = 0xFF,
			DNS_TYPE_ANY = 0xFF,
			DNS_TYPE_WINS = 0xFF01,
			DNS_TYPE_WINSR = 0xFF02,
			DNS_TYPE_NBSTAT = DNS_TYPE_WINSR
		}
    }
}