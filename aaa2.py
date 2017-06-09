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


subprocess.Popen('tcpdump.exe -C 100 -n -nn -f -s 0 -w video.tmp -W 2 tcp port 80',shell=True)

def read_pcap(pcap_name):
	pkt = rdpcap(pcap_name)
	print len(pkt)
	
def check_file_exists():           #tcpdump会将抓包结果写入两个文件,如果两个文件均存在则代表已经有一个文件可以开始读取
	if os.path.exists('video.tmp0') and os.path.exists('video.tmp1'):
		return 1
		
def check_write_done():				#判断两个文件大小之差,大的那个是已经写入结束的
	if int(os.path.getsize('video.tmp0') - os.path.getsize('video.tmp1')) > 50000000:
		return 'video.tmp0'
	if int(os.path.getsize('video.tmp1') - os.path.getsize('video.tmp0')) > 50000000:
		return 'video.tmp1'
		
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
		check_target_change(read_file)
