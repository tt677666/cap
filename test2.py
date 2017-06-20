#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys,time,os,subprocess,gzip,struct
print sys.getdefaultencoding()
reload(sys)
sys.setdefaultencoding('utf-8')
print sys.getdefaultencoding()
from scapy.all import *
#from btbb import *
from scapy.data import MTU
from scapy.layers import http

#'========================global================================='
file_name='tmp'
file_info={}
file_info['video_tmp0'] = 0
file_info['video_tmp1'] = 0
pre_len = 0
video_list = []
#'========================global================================='
time.sleep(1)
if os.path.exists('video_tmp0'):
	os.remove('video_tmp0')
if os.path.exists('video_tmp1'):
	os.remove('video_tmp1')

subprocess.Popen('tcpdump.exe -C 10 -W 2 -B 1 -n -nn -f -s 0 -w video_tmp  tcp port 80',shell=True)

def open_pcap(filename,stop=True,output = 'packet'):
	global file_info
	print 2
	try:
		f = gzip.open(filename,"rb")
		magic = f.read(4)
	except IOError:
		f = open(filename,"rb")
		magic = f.read(4)
	print f.name
	if magic == "\xa1\xb2\xc3\xd4": #big endian
		endian = ">"
	elif  magic == "\xd4\xc3\xb2\xa1": #little endian
		endian = "<"
	else:
		raise Scapy_Exception("Not a pcap capture file (bad magic)")
	hdr = f.read(20)
	if len(hdr)<20:
		raise Scapy_Exception("Invalid pcap file (too short)")
	vermaj,vermin,tz,sig,snaplen,linktype = struct.unpack(endian+"HHIIII",hdr)

	linktype = linktype
    
	while True:
		header_loc = f.tell()
		b = check_file_change()
		print b

		try:
			hdr = f.read(16)
			
			while len(hdr) < 16:
				f.seek(header_loc)
				if f.name == b:
					raise KeyboardInterrupt
				time.sleep(1)
				hdr = f.read(16)
			
			sec,usec,caplen,wirelen = struct.unpack(endian+"IIII", hdr)
			body_loc = f.tell()
			print caplen
			s = f.read(caplen)[:MTU]
			
			while len(s) < caplen:
				f.seek(body_loc)
				if f.name == b:
					raise KeyboardInterrupt
				time.sleep(1)
				s = f.read(caplen)[:MTU]
			
			result = s,(sec,usec,wirelen)
			if output == 'raw':
				result = s
			elif output == 'packet':
				result = Ether(s)
			yield result
		except KeyboardInterrupt:
			f.seek(header_loc)
			f.close()
			break

def check_file_change():
	global file_info
	while True:
		if os.path.exists('video_tmp0'):
			file0_size = os.path.getsize('video_tmp0')
			if  file0_size - file_info['video_tmp0'] > 0 or file0_size - file_info['video_tmp0'] < 0:
				file_info['video_tmp0'] = file0_size
				return 'video_tmp0'
				break
		if os.path.exists('video_tmp1'):
			file1_size = os.path.getsize('video_tmp1')
			if file1_size - file_info['video_tmp1'] > 0 or file1_size - file_info['video_tmp1'] < 0:
				file_info['video_tmp1'] = file1_size
				return 'video_tmp1'
				break
		else:
			continue
'''
def read_pcap(pcap_name):
	#global pre_len,file_name,video_list

	if file_name != pcap_name:
		pre_len = 0
		file_name = pcap_name
		
	pkt = rdpcap(pcap_name)
	#video_list.append(len(video_list):)
	for k in video_list[len(video_list):len(pkt)]:
		video_list.append(k)
	if len(pkt) > pre_len:
		
		a = 'read more part'
		pre_len = len(pkt)

	pkt = rdpcap(pcap_name)
	print len(pkt),pcap_name

	

	


def check_target_change(target_file):
	#global file_name
	#if file_name != target_file:
	read_pcap(target_file)
		#file_name = target_file
	#else:
		#pass
'''
while True:

	read_file = check_file_change()
	a = open_pcap(read_file,stop=True,output = 'packet')
	for k in a:
		print k.summary()

	print 'filechange'
