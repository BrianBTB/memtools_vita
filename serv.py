#!/usr/bin/env python2
"""
    This is the 'web server' that serves files to the Vita
    and also acts as a command center.
    P.S: This server most likely cannot be used as is for anything else other
    than fiddling with the Vita.
"""

import struct
import SocketServer
import SimpleHTTPServer
import urlparse
import urllib2
from capstone import *
from progress.bar import Bar

PORT = 8888

"""
    Dump given data to fname
"""
def dump_data(data, fname):
    fp = open("dump/"+ fname,"a+b")
    fp.write(data)
    fp.close()

"""
    Display src in a hex-editor-file fashion
"""
def display_data(addr, src, length=16, n=8):
    filter_=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    result=[]
    for i in xrange(0, len(src), length):
       s = src[i:i+length]
       hexa = ''.join(["%02X"%ord(x) for x in s])
       hexa = ' '.join(["".join(hexa[j:j+n]) for j in range(0, len(hexa), n)])
       printable = s.translate(filter_)
       result.append("%08X   %-*s   %s\n" % (addr + i, length*3, hexa, printable))
    return ''.join(result)


"""
    Disassemble data starting at addr
"""
def disassemble(addr, data, thumb=False):
    none = 0                                            # disassed at least on
    if thumb == True:
        mode = CS_MODE_THUMB
    else:
        mode = CS_MODE_ARM
    md = Cs(CS_ARCH_ARM, mode + CS_MODE_LITTLE_ENDIAN)
    disassed = md.disasm(data, addr)
    for i in disassed:
        none = 1
        print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
    if none != 1:
        print "Couldn't disassemble at 0x%x"%(addr)

"""
	Dissassembles for the automatic dump

def disassembledump(addr, data):
    none = 0                                            # disassed at least on
    mode = CS_MODE_ARM
    md = Cs(CS_ARCH_ARM, mode + CS_MODE_LITTLE_ENDIAN)
    disassed = md.disasm(data, addr)
    for i in disassed:
        none = 1
	print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
        
    if none != 1:
        print "Couldn't disassemble at 0x%x"%(addr)
    return "lol"
"""
"""
    The good guy
"""
class VitaWebServer(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """
        GET Request Handler
        Used for debugging and interactive shell stuff
    """
    def do_GET(self): 
        # debugging info
        if self.path.startswith('/Debug'):
            print '[+] DBG: ',
            parsed = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            dbg = parsed['dbg'][0]
            print dbg
        # handle dump
        elif self.path == '/Command':
            sockfd = self.request
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            cmd = raw_input("%> ")
            self.wfile.write(cmd)
        # normal requests
        else:
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    """
        POST Request Handler
    """
    def do_POST(self):
        length = int(self.headers.getheader('content-length'))
        if length:
            rdata = self.rfile.read(length)
            rdata = urlparse.parse_qs(rdata)
            addr = 0
            extra = ""

            try:
                addr = int(rdata['addr'][0])
            except KeyError:
                print "[+] Warning: addr not received"
            try:
                data = rdata['data'][0]
            except KeyError:
                print "[+] Error: dump not received"
                return
            try:
                typ = rdata['type'][0]
            except KeyError:
                print "[+] Error: msg type not received"
                return

            try:
                extra = rdata['extra'][0]
            except KeyError:
                pass

            if(typ == 'read'):
                print display_data(addr, data.decode('hex'))
            if(typ == 'dis'):
                if(extra == "thumb"):
                    disassemble(addr, data.decode('hex'), thumb=True)
                else:
                    disassemble(addr, data.decode('hex'))

            if(typ == 'dis_res'):
                if(extra == "thumb"):
                    disassemble(addr, data.decode('hex'), thumb=True)
                else:
                    disassemble(addr, data.decode('hex'))




                    """



	    if(typ == 'resolve'):
                
		adr = disassembledump(addr,data.decode('hex'))
		print "hi from python", adr
		self.wfile.write("resolve " + adr + " " + extra)
		"""

            if(typ == 'dump'):
                fname = extra
                dump_data(data.decode('hex'), fname)
            
                

SocketServer.TCPServer.allow_reuse_address = True
server = SocketServer.TCPServer(('', PORT), VitaWebServer)
server.serve_forever()
