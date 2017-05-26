from scapy.all import *
from scapy.layers import http
import struct,codecs
next_ack = -111
tcp_sport = 0
dataflow = []
tcp_flag = 0

def search_list(seq,tmp_list1):
	value = -1
	for i in tmp_list1:
		print seq,i[TCP].seq
		if seq == i[TCP].seq:
			value == i[TCP].seq
			
			break
		else:
			continue
	print value
	return value
def order_packet(tmp_list):
	new_tmp = []
	print tmp_list[0][TCP].seq,len(tmp_list[0])
	next_seq = tmp_list[0][TCP].seq+len(tmp_list[0][TCP].payload)
	new_tmp.append(tmp_list[0])
	tmp_list.pop(0)
	
	while search_list(next_seq,tmp_list)>=0:
		
		
		#print len(tmp_list)
		for k in tmp_list[:]:
			print k[TCP].seq,len(k)
			if next_seq == k[TCP].seq:
				new_tmp.append(k)
				tmp_list.remove(k)
				next_seq = k[TCP].seq+len(k[TCP].payload)
				
				break
			else:
				continue
	return new_tmp
def http_header(packet):
	global next_ack,dataflow,tcp_flag
	if packet.haslayer(http.HTTPRequest):
		
		http_layer = packet.getlayer(http.HTTPRequest)

		if http_layer.fields['Path'].find('.flv?wsAuth')>0:
			print 'woshihttprequest'
			global next_ack,tcp_sport
			print http_layer.fields['Host']+http_layer.fields['Path']

 			next_ack = len(packet) - 54 + packet[TCP].seq
			print 'next_ack is',next_ack
			tcp_sport = packet[TCP].sport

	if packet[TCP].dport == tcp_sport and (packet[TCP].ack == next_ack) or (packet[TCP].ack == (next_ack+1)):
		
		if 1 == tcp_flag:
			if len(dataflow)<1000:
					
				dataflow.append(packet)
			else: 
				new_tmp1 = order_packet(dataflow)
				for l in new_tmp1:
					print l[TCP].seq,len(l[TCP].payload)
					with open('dy.flv','ab') as f:
						f.write(str(l[TCP].payload))
				exit()
		else:

			if str(packet[TCP].payload).find('FLV')>=0:
				dataflow.append(packet)
				tcp_flag = 1
				print 'tcp_flag is',tcp_flag
			

packet=sniff(filter='tcp port 80',prn=http_header,store=0)
'''
import binascii
filename = 'test.dat'
with open(filename, 'rb') as f:
    content = f.read()
print(binascii.hexlify(content))
'''
