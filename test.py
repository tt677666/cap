from scapy.all import *
from scapy.layers import http
'''
try:
    import scapy.all as scapy
except ImportError:
    import scapy

from scapy.all import *
try:
    # This import works from the project directory
    import scapy_http.http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

import pcap
import dpkt
import binascii


a=pcap.pcap()
a.setfilter('tcp port 80')
a.show()

eth=dpkt.ethernet.Ethernet(j)

print ("%s %x",i,eth)
print binascii.hexlify(j)
print '============='

packets = scapy.rdpcap('C:\\Users\\john\\Desktop\\livecapture\\aaa.pcap')
for p in packets:
	p.show()
'''
def http_header(packet):
	if not packet.haslayer(http.HTTPRequest):
		#print packet[TCP]
		return
	http_layer = packet.getlayer(http.HTTPRequest)
	http_layer1 = packet.getlayer(http.HTTPResponse)
	print type(http_layer.fields),http_layer1
	'''
	
	ip_layer = packet.getlayer(IP)
	print ip_layer
	'''
packet=sniff(filter='tcp port 80',prn=http_header,store=0)




