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
file_info = {}

subprocess.Popen('tcpdump.exe -C 10 -n -nn -f -s 0 -w video.tmp  tcp port 80',shell=True)

time.sleep(1)

for k in os.listdir('\\'):
	if os.path.isfile(k):
		if k.find('video.tmp')==0:
			file_info[k]=os.path.getsize(k)
def check_file_change(file_name_and_size):
	while True:
		for m in file_name_and_size:
			for i in os.listdir('\\'):
				if i.find('video.tmp')==m:
					return
	
file_info['video_tmp0'],file_info['video_tmp1'] = 0
def check_file_change():
	global file_info
	while True:
		if os.path.exists('video_tmp0'):
			file0_size = os.path.getsize('video_tmp0')
			if  file0_size - file_info['video_tmp0'] > 0:
				file_info['video_tmp0'] = file0_size
				return 'video_tmp0'
				break
		if os.path.exists('video_tmp1'):
			file1_size = os.path.getsize('video_tmp1')
			if os.path.getsize('video_tmp1') - file_info['video_tmp1'] > 0:
				file_info['video_tmp1'] = file1_size
				return 'video_tmp1'
				break
		else:
			continue

def read_pcap(pcap_name):
	pkt = rdpcap(pcap_name)
	print len(pkt),pcap_name
	for k in pkt:
		if str(k).find('.flv?wsAuth')>0:
			print k[TCP].seq
	
def check_file_exists():           #tcpdump会将抓包结果写入两个文件,如果两个文件均存在则代表已经有一个文件可以开始读取
	if os.path.exists('video.tmp0') and os.path.exists('video.tmp1'):
		return 1
		
def check_write_done():				#判断两个文件大小之差,大的那个是已经写入结束的
	while True:
		if int(os.path.getsize('video.tmp0') - os.path.getsize('video.tmp1')) > 5000000:
			return 'video.tmp0'
			break
		if int(os.path.getsize('video.tmp1') - os.path.getsize('video.tmp0')) > 5000000:
			return 'video.tmp1'
			break
		else:
			continue
		
def check_target_change(target_file):
	global file_name
	if file_name != target_file:
		read_pcap(target_file)
		file_name = target_file
	else:
		pass
	
while True:
	start_flag = check_file_exists()
	if 1 == start_flag:
		read_file = check_write_done()
		#print read_file,type(read_file)
		check_target_change(read_file)
