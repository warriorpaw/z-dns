from SocketServer import BaseRequestHandler, ThreadingUDPServer , StreamRequestHandler , ThreadingTCPServer
from cStringIO import StringIO
from fnmatch import fnmatch
import os
import socket
import struct
import time , thread , threading
import re
import sys

DNS_TYPE_A = 1
DNS_CLASS_IN = 1
DNS_CONFIG_FILE = 'dns.conf'
DNS_HOSTS_FILE = 'dns.hosts'
DNS_SWITCH_FILE = 'dns.switch'
DNS_LOCAL_PATH = '.\\'
reg_IP = '((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)'
ALL_LOG_LOCK = thread.allocate_lock()
SWI_LOG_LOCK = thread.allocate_lock()
dnsserver = [None,None]

def check_file():
    old_info = ( os.stat("dns.conf").st_mtime ,os.stat("dns.hosts").st_mtime ,os.stat("dns.switch").st_mtime )
    while dnsserver[0].isRun() :
        time.sleep(60)
        tmp_info = ( os.stat("dns.conf").st_mtime ,os.stat("dns.hosts").st_mtime ,os.stat("dns.switch").st_mtime )
        if old_info != tmp_info :
            dnsserver[0].reLoad()
            old_info = tmp_info
    if (not dnsserver[0].isRun()):
        dnsserver[1].killServer()

class dns_server(threading.Thread):
    dnsserver = None
    over = False
    def __init__(self):
        threading.Thread.__init__(self)
        
    def run(self):
        while not self.over:
            self.dnsserver = DNSProxyServer()
            self.dnsserver.serve_forever()
        
    def reLoad(self):
        if not self.over:
            self.dnsserver.shutdown()
            self.dnsserver.server_close()
            os.system("ipconfig /flushdns")
        
    def killServer(self):
        if not self.over:
            self.over = True
            self.dnsserver.shutdown()
            self.dnsserver.server_close()
        
    def isRun(self):
        return not self.over

class dns_server_ByTCP(threading.Thread):
    dnsserver = None
    over = False
    def __init__(self):
        threading.Thread.__init__(self)
        
    def run(self):
        while not self.over:
            self.dnsserver = DNSProxyServer_ByTCP()
            self.dnsserver.serve_forever()
        
    def killServer(self):
        if not self.over:
            self.over = True
            self.dnsserver.shutdown()
            self.dnsserver.server_close()

def main():
    dnsserver[0] = dns_server()
    dnsserver[0].start()
    dnsserver[1] = dns_server_ByTCP()
    dnsserver[1].start()
    checkfile = threading.Thread(target = check_file , args =()) 
    checkfile.start()
    
class Struct(object):
    def __init__(self, **kwargs):
        for name, value in kwargs.items():
            setattr(self, name, value)

def parse_dns_message(data):
    message = StringIO(data)
    message.seek(4)
    c_qd, c_an, c_ns, c_ar = struct.unpack('!4H', message.read(8))
    question = parse_dns_question(message)
    for i in range(1, c_qd):
        parse_dns_question(message)
    records = []
    for i in range(c_an+c_ns+c_ar):
        records.append(parse_dns_record(message))
    return Struct(question=question, records=records)

def parse_dns_question(message):
    qname = parse_domain_name(message)
    qtype, qclass = struct.unpack('!HH', message.read(4))
    end_offset = message.tell()
    return Struct(name=qname, type_=qtype, class_=qclass, end_offset=end_offset)

def parse_dns_record(message):
    parse_domain_name(message)
    message.seek(4, os.SEEK_CUR)
    ttl_offset = message.tell()
    ttl = struct.unpack('!I', message.read(4))[0]
    rd_len = struct.unpack('!H', message.read(2))[0]
    message.seek(rd_len, os.SEEK_CUR)
    return Struct(ttl_offset=ttl_offset, ttl=ttl)

def _parse_domain_labels(message):
    labels = []
    len = ord(message.read(1))
    while len > 0:
        if len >= 64:
            len = len & 0x3f
            offset = (len << 8) + ord(message.read(1))
            mesg = StringIO(message.getvalue())
            mesg.seek(offset)
            labels.extend(_parse_domain_labels(mesg))
            return labels
        else:
            labels.append(message.read(len))
            len = ord(message.read(1))
    return labels

def parse_domain_name(message):
    return '.'.join(_parse_domain_labels(message))

def addr_p2n(addr):
    return socket.inet_aton(addr)

def buildrspdata(reqdata,end_offset,packed_ip):
    rspdata = reqdata[:2] + '\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
    rspdata += reqdata[12:end_offset]
    rspdata += '\xc0\x0c'
    rspdata += '\x00\x01'
    rspdata += '\x00\x01\x00\x00\x07\xd0'
    rspdata += '\x00' + chr(len(packed_ip))
    rspdata += packed_ip
    return rspdata


class DNSProxyHandler_ByTCP(StreamRequestHandler):
    def handle(self):
        data = self.connection.recv(1024)
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("8.8.8.8",53))
        s.send(data)
        r_data = s.recv(1024)
        self.wfile.write(r_data)
        s.close()

class DNSProxyHandler(BaseRequestHandler):
    def handle(self):
        reqdata, sock = self.request
        req = parse_dns_message(reqdata)
        q = req.question
        if self.server.Log_all :
            tmp = ''+q.name.ljust(30) + '  ' +time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+ ' Type:' + str(q.type_)+'\n'
            ptmp = DNS_LOCAL_PATH+'All_query.log'
            ALL_LOG_LOCK.acquire()
            log = open(ptmp ,'a')
            log.write(tmp)
            log.close()
            ALL_LOG_LOCK.release()
        if (q.type_ == DNS_TYPE_A) and (q.class_ == DNS_CLASS_IN):
            for ip,name in self.server.hostslist: 
                if fnmatch(q.name.upper(), name.upper()):
                    if ip == 'skip':
                        break
                    rspdata = buildrspdata(reqdata,q.end_offset,ip)
                    sock.sendto(rspdata, self.client_address)
                    return

            for name,CorF in self.server.switchlist:
                if fnmatch(q.name.upper(), name.upper()):
                    rspdata = self._get_response(reqdata , CorF)
                    if rspdata:
                        sock.sendto(rspdata, self.client_address)
                    return
            
            _tmp = q.name+'\n'
            _ptmp = DNS_LOCAL_PATH+'switch.log'
            SWI_LOG_LOCK.acquire()
            log = open(_ptmp,'a')
            log.write(_tmp)
            log.close()
            SWI_LOG_LOCK.release()
            rspdata = self._get_response(reqdata , True)
            if rspdata:
                sock.sendto(rspdata, self.client_address)
            return
        else:
            rspdata = self._get_response(reqdata , True)
            if rspdata:
                sock.sendto(rspdata, self.client_address)
            return

    def _get_response(self, data ,CorF):
        con = 0
        rspdata = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((self.server.servers[(not CorF) and 1 or 0], 53)) 
        while not rspdata and con <4:
            try:
                con += 1
                sock.sendall(data)
                sock.settimeout(3)
                rspdata = sock.recv(65535)
            except:
                rspdata = None
        sock.close()
        return rspdata

def loadconf():
    DNS_SERVER = [None,None]
    log_all = [False]
    def readline(line):
        if (not line.startswith('#')) and len(line) > 2:
            parts = line.strip().split()[:2]
            if parts[0] == 'Note_Down_All':
                if parts[1] == '1':
                    log_all[0] = True
                return
            if re.search(reg_IP, parts[1]):
                if parts[0] == 'Foreign_DNS':
                    DNS_SERVER[0]=parts[1]
                    return
                if parts[0] == 'Celestial_DNS':
                    DNS_SERVER[1]=parts[1]
                    return
            print 'Warning:',DNS_CONFIG_FILE,' has some error at ',line
                    
    with open(DNS_LOCAL_PATH+DNS_CONFIG_FILE) as conf:
        for line in conf:
            readline(line)
    if DNS_SERVER[0] and DNS_SERVER[1]:
        return tuple(DNS_SERVER),log_all[0]
    else:
        return None,None
    
def lodehosts():
    hostsline = []
    def readline(line):
        if (not line.startswith('#')) and len(line) > 2:
            parts = line.strip().split()[:2]
            if parts[0] == 'skip':
                return 'skip',parts[1]
            if re.search(reg_IP, parts[0]):
                try:
                    return addr_p2n(parts[0]),parts[1]
                except:
                    return None
            return None
        return None
                
    with open(DNS_LOCAL_PATH+DNS_HOSTS_FILE) as hosts:
        for line in hosts:
            htmp = readline(line)
            if htmp:
                hostsline.append(htmp)
        return tuple(hostsline)
            
def loadswitchfile():
    CorF = [False]
    switchlist = []
    def readline(line):
        if (not line.startswith('#')) and len(line) > 2:
            if line.startswith('[Celestial Urls]'):
                CorF[0] = False
                return
            if line.startswith('[Foreign Urls]'):
                CorF[0] = True
                return
            if len(line.strip().split()) == 1:
                switchlist.append(("".join(line.strip()),CorF[0]))
            else:
                print 'warning: something is error at ' , line , ' in file ' , DNS_SWITCH_FILE
    with open(DNS_LOCAL_PATH+DNS_SWITCH_FILE) as switch:
        for line in switch:
            readline(line)
        return tuple(switchlist)

class DNSProxyServer(ThreadingUDPServer):
    def __init__(self):
        log = open(DNS_LOCAL_PATH+'switch.log','w')
        log.write('This file will be clear up when restar !\nUnswitched DNS query :\n')
        log.close()
        self.hostslist = lodehosts()
        self.switchlist = loadswitchfile()
        self.servers,self.Log_all = loadconf()
        if not self.servers:
            print 'Loding ',DNS_CONFIG_FILE,' false '
            sys.exit(0)
        print 'z.DNS is running now ! \nUsing DNS : ' + self.servers[0] + '  ' + self.servers[1] 
        ThreadingUDPServer.__init__(self, ('127.0.0.1', 53), DNSProxyHandler)

class DNSProxyServer_ByTCP(ThreadingTCPServer):
    def __init__(self):
        ThreadingTCPServer.__init__(self, ('127.0.0.1', 53), DNSProxyHandler_ByTCP)
            
if __name__ == '__main__':
    main()
