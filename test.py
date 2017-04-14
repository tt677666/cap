from scapy.all import *
from scapy.layers import http
import struct
next_ack = -1
tcp_sport = 0
dataflow = []
def check_ack(pkt,ensure_ack):
	print 222222222222
	if pkt[TCP].ack == ensure_ack:
		print pkt,111111111111111111

def http_header(packet):
	global next_ack,dataflow
	if packet.haslayer(http.HTTPRequest):
		print 'woshihttprequest'
		http_layer = packet.getlayer(http.HTTPRequest)

		if http_layer.fields['Path'].find('.flv?wsAuth')>0:
			global next_ack,tcp_sport
			print http_layer.fields['Host']+http_layer.fields['Path']
			#print len(packet) + 1,type(len(packet))
			#print packet[TCP].seq,type(packet[TCP].seq)
 			next_ack = len(packet) - 54 + packet[TCP].seq
			print 'next_ack is',next_ack
			#tcp_sport = packet[TCP].sport
	#print 'seq is ',packet[TCP].seq
	#if next_ack ==  packet[TCP].seq and tcp_sport == packet[TCP].sport:
		#print 'flag is ',packet[TCP].flags
	if packet[TCP].ack == next_ack:
		if len(packet)> 60:
			print type(hexdump(packet))
			#bytes=struct.pack('i',hexdump(packet))
			file_object=open('dy.flv','a')
			print 1111111111111111222222222222
			print packet[TCP].payload,type(packet[TCP].payload)
			file_object.write(packet[TCP].payload)
			file_object.close()
			#dataflow.append(hexdump(packet))
		if packet.haslayer(http.HTTPResponse):
		    http_layer1 = packet.getlayer(http.HTTPResponse)
		    if str(http_layer1).find('302'):
				dataflow = []
				print 'the list had been reset'
			

packet=sniff(filter='tcp port 80',prn=http_header,store=0)
