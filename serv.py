#!/usr/bin/env python2
"""
    This is the 'web server' that serves files to the Vita
    and also acts as a command center.
    P.S: This server most likely cannot be used as is for anything else other
    than fiddling with the Vita.
"""

import sys
import socket,SocketServer
import SimpleHTTPServer
import os
import urlparse
from capstone import CS_MODE_THUMB, CS_MODE_ARM, Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN

PATH = os.path.dirname(os.path.realpath(__file__))
CURRENT_DUMP_FILE_NAME = ""

def dump_data(data, file_name):
    """
    Dump given data to file

    :type file_name: str
    :param file_name: The dump data file name
    """
    directory = PATH+"/dump/"
    if not os.path.exists(directory):
        os.makedirs(directory)

    file_pointer = open(directory + file_name, "a+b")
    file_pointer.write(data)
    file_pointer.close()

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
        print "0x%x:\t%s    %s" %(i.address, i.mnemonic, i.op_str)
    if none != 1:
        print "Couldn't disassemble at 0x%x"%(addr)

"""
    Print available commands
"""
def print_help(cmd):
    cmd_s = cmd.split(" ");
    if len(cmd_s) == 1:
        print "\tautodump"
        #print "\tsavemods"
        print "\tx <addr> <len>"
        print "\tdis <addr> <len> <mode>"
        print "\tdump <addr> <len> <fname>"
        print "\tss <begaddr> <endaddr> <pattern>"
        print "\thelp <command>"
        print "\treload"
        print "\texit"
        print "to get command help, use help <command>"
    else:
        if cmd_s[1] == 'autodump':
            print "\tautodump : use to begin recursively resolving the modules"
        elif cmd_s[1] == 'x':
            print "\tx <addr> <len> : to display <len> bytes from <addr> in a hex-editor-like fashion"
        elif cmd_s[1] == 'dis':
            print "\tdis <addr> <len> <mode> : to disassemble <len> bytes from <addr> in <mode> (thumb or arm, latter is default)"
        elif cmd_s[1] == 'dump':
            print "\tdump <addr> <len> <fname> : to dump <len> bytes from <addr> to <fname>"
        elif cmd_s[1] == 'ss':
            print "\tss <begaddr> <endaddr> <pattern> : to search for the string <pattern> in [begaddr, endaddr["
        elif cmd_s[1] == 'reload':
            print "\treload : to reload/reset everything"
        elif cmd_s[1] == 'exit':
            print "\texit : to exit"
        else:
            print "\thelp <command> : prints help about <command>"
"""
    The good guy
"""
class VitaWebServer(SimpleHTTPServer.SimpleHTTPRequestHandler):

    """
        GET Request Handler
        Used for debugging and interactive shell stuff
    """
    mods = []
    def do_GET(self):
        
        # debugging info
        if self.path.startswith('/Debug'):
            try:
                print '[+] DBG: ',
                parsed = urlparse.parse_qs(urlparse.urlparse(self.path).query)
                dbg = parsed['dbg'][0]
                print dbg
                if dbg == 'Exiting... (Call by user)':
                    os._exit(0)
            except KeyError:
                print "[+] Warning: Dbg error"
        # handle dump
        elif self.path == '/Command':   			
            sockfd = self.request
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            if len(self.mods) > 0:
                cmd = self.mods.pop(0)
            else:
                localCmd = True
                while localCmd == True:
                    cmd = raw_input("%> ")
		    if cmd.startswith('help'):
                        print_help(cmd)
                    else:
                        localCmd = False
            try:
                self.wfile.write(cmd)
            except:
                print '[+] DBG: Exiting... (Socket Error)'
                os._exit(0)
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
                mode = CS_MODE_ARM
                md = Cs(CS_ARCH_ARM, mode + CS_MODE_LITTLE_ENDIAN)
                disassed = md.disasm(data.decode('hex'), addr)
                ops = []
                ptrstr = ""
                print "Parsing: " + extra
                for i in disassed:
                    print "0x%x:\t%s    %s" %(i.address, i.mnemonic, i.op_str)
                    if i.mnemonic == "SVC":
                        print "Could not resolve " + extra + " (syscall) "
                        return
                    ops.append(i.op_str[7:])
                    


                ptrstr = "0x"+ops[1].rjust(4,'0')+ops[0].rjust(4,'0')
                cmdstr = "resolve " + ptrstr + " " + extra
                print cmdstr
                if (int(ptrstr,16) > 0x40000000) and (int(ptrstr,16) < 0xE000000000):
                    self.mods.append(cmdstr)
                else:
                    print "Could not resolve " + extra + " (invalid address) "
                print "----"
            """    
            if(typ == 'dump'):
                fname = extra
                dump_data(data.decode('hex'), fname)
            """
            if typ == 'dump':
                global CURRENT_DUMP_FILE_NAME
                if CURRENT_DUMP_FILE_NAME == "":
                    #If this is the initial dump
                    CURRENT_DUMP_FILE_NAME = extra
                    #check if this file already exists
                    self.dump_directory_initializer(extra)
                elif not extra.startswith(CURRENT_DUMP_FILE_NAME):
                    #If this is a different dump
                    self.dump_directory_initializer(extra)
                    CURRENT_DUMP_FILE_NAME = extra

                dump_data(data.decode('hex'), CURRENT_DUMP_FILE_NAME)
            
    @staticmethod
    def dump_directory_initializer(file_name):
        """
        Initialise the dump directory, by creating and also if a file exist, it renames it to prevent overwrite

        :param file_name: The file name
        :type file_name: str

        :return: bool
        """
        try:
            directory = PATH+"/dump/"
            if not os.path.exists(directory):
                os.makedirs(directory)
			
            if file_name != "":
                for root, dirs, files in os.walk(directory):
                    for individual_file in files:
                        if file_name == individual_file:
                            full_path = directory + file_name
                            #generate a unique name extension
                            current_milli_time = int(round(time.time() * 1000))
                             # Separate base from extension
                            base, extension = os.path.splitext(file_name)
                            new_file_name = base + "_" + str(current_milli_time) + extension
                            os.rename(full_path, directory + new_file_name)
            return True
        except Exception, ex:
            print '[+] DBG Directory Initializer Exception: ' + str(ex)
            return False                

try:
    PORT = int(sys.argv[1])
except:
    PORT = 8888


#src : http://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("gmail.com",80))
localIP = s.getsockname()[0]
s.close()

print "Starting server on " + localIP + ":" + str(PORT)

SocketServer.TCPServer.allow_reuse_address = True
server = SocketServer.TCPServer(('', PORT), VitaWebServer)
server.serve_forever()
