from scapy.all import *
from scapy.layers import http
def check_ack(pkt,ensure_ack):
	print 222222222222
	if pkt[TCP].ack == ensure_ack:
		print pkt,111111111111111111

def http_header(packet):
	
	if packet.haslayer(http.HTTPRequest):
		next_ack =0
		print 'woshihttprequest'
		http_layer = packet.getlayer(http.HTTPRequest)

		if http_layer.fields['Path'].find('.flv?wsAuth')>0:
			
			print http_layer.fields['Host']+http_layer.fields['Path']
			print len(packet) + 1,type(len(packet))
			print packet[TCP].seq,type(packet[TCP].seq)
 			next_ack = len(packet) - 54 + packet[TCP].seq
			print next_ack
	#check_ack(packet,next_ack)
	print next_ack
	

packet=sniff(filter='tcp port 80',prn=http_header,store=0)
