from scapy.all import *
from scapy.layers import http
next_ack = 0
tcp_sport = 0
def check_ack(pkt,ensure_ack):
	print 222222222222
	if pkt[TCP].ack == ensure_ack:
		print pkt,111111111111111111

def http_header(packet):
	
	if packet.haslayer(http.HTTPRequest):
		print 'woshihttprequest'
		http_layer = packet.getlayer(http.HTTPRequest)

		if http_layer.fields['Path'].find('.flv?wsAuth')>0:
			global next_ack,tcp_sport
			print http_layer.fields['Host']+http_layer.fields['Path']
			#print len(packet) + 1,type(len(packet))
			#print packet[TCP].seq,type(packet[TCP].seq)
 			next_ack = len(packet) + 1 - 54 + packet[TCP].seq
			#print 'next_ack is',next_ack
			tcp_sport = packet[TCP].sport
	#print 'seq is ',packet[TCP].seq
	#if next_ack ==  packet[TCP].seq and tcp_sport == packet[TCP].sport:
		#print 'flag is ',packet[TCP].flags
		
	if packet.haslayer(http.HTTPResponse):
		http_layer1 = packet.getlayer(http.HTTPResponse)
		for k in http_layer1:
			print k

packet=sniff(filter='tcp port 80',prn=http_header,store=0)
