#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys,time,os,subprocess
print sys.getdefaultencoding()
reload(sys)
sys.setdefaultencoding('utf-8')
print sys.getdefaultencoding()
from scapy.all import *
from scapy.layers import http

file_name='tmp'
file_info={}
file_info['video_tmp0'] = 0
file_info['video_tmp1'] = 0

os.remove('video_tmp0')
os.remove('video_tmp1')

subprocess.Popen('tcpdump.exe -C 10 -W 2 -n -nn -f -s 0 -w video_tmp  tcp port 80',shell=True)

time.sleep(1)


def check_file_change():
	global file_info
	while True:
		if os.path.exists('video_tmp0'):
			file0_size = os.path.getsize('video_tmp0')
			if  file0_size - file_info['video_tmp0'] > 0 or file0_size - file_info['video_tmp0'] < 0:
				file_info['video_tmp0'] = file0_size
				print 'video_tmp0'
				return 'video_tmp0'
				break
		if os.path.exists('video_tmp1'):
			file1_size = os.path.getsize('video_tmp1')
			if file1_size - file_info['video_tmp1'] > 0 or file1_size - file_info['video_tmp1'] < 0:
				file_info['video_tmp1'] = file1_size
				print 'video_tmp1'
				return 'video_tmp1'
				break
		else:
			continue

def read_pcap(pcap_name):
	pkt = rdpcap(pcap_name)
	print len(pkt),pcap_name

	

		

def check_target_change(target_file):
	global file_name
	if file_name != target_file:
		read_pcap(target_file)
		file_name = target_file
	else:
		pass

while True:

	read_file = check_file_change()
	#print read_file,type(read_file)
	check_target_change(read_file)
