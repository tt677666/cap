from scapy.all import *
from scapy.layers import http

def call_back(packet):
	if not packet.haslayer(http.HTTPRequest):
		#for p in packet:
		print packet[TCP].flags
		return
	http_layer = packet.getlayer(http.HTTPRequest)
	print type(http_layer.fields)
		
	
		

sniff(filter='tcp port 80',prn=call_back,store=0)

'''
def writer_proc():
	port=8081
	host='127.0.0.1'
	s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	a =pcap.pcap()
	
	for l in a:
		print '============================'
		print type(l),type(l[0]),type(l[1])
		print binascii.hexlify(l[1])
		print '============================'
		s.sendto(l[1],(host,port))
		
def reader_proc():
	port=8081
	s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	s.bind(('127.0.0.1',port))
	while True:
		data,addr=s.recvfrom(20480)
		
		#print('Received:',data,'from',addr)
		eth = dpkt.ethernet.Ethernet(data)
		if not isinstance(eth.data, dpkt.ip.IP):
			continue
		ip = eth.data
		if isinstance(ip.data, dpkt.tcp.TCP):
			tcp = ip.data
			#print 111111111111111
			try:
				request = dpkt.http.Request(tcp.data)
			except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
				continue
			#print type(repr(request))
			#print time.asctime( time.localtime(time.time()) ),'HTTP request: %s\n' % repr(request)
if __name__ == "__main__":
	p1 = multiprocessing.Process(target = writer_proc, args = ())
	p2 = multiprocessing.Process(target = reader_proc, args = ())
	p1.start()
	p2.start()
'''
	
