from scapy.all import *
from scapy.layers import http





def http_header(packet):
	if not packet.haslayer(http.HTTPRequest):
		#print packet[TCP]
		return
	http_layer = packet.getlayer(http.HTTPRequest)
	http_layer1 = packet.getlayer(http.HTTPResponse)
	print type(http_layer.fields),http_layer1

packet=sniff(filter='tcp port 80',prn=http_header,store=0)




