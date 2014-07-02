#!/usr/bin/env python
#coding=utf-8
#读取pcap文件，解析相应的信息，为了在记事本中显示的方便，把二进制的信息
import json
import struct
import os
from os.path import getsize
from pro import *
size=getsize('testall.pcap')
fpcap = open('testall.pcap','rb')
ftxt = open('result.json','w')

#string_data = fpcap.read()

#pcap文件包头解析
pcap_header = {}
pcap_header['magic_number'] = fpcap.read(4)
pcap_header['version_major'] = fpcap.read(2)
pcap_header['version_minor'] = fpcap.read(2)
pcap_header['thiszone'] = fpcap.read(4)
pcap_header['sigfigs'] = fpcap.read(4)
pcap_header['snaplen'] = fpcap.read(4)
pcap_header['linktype'] = fpcap.read(4)
#print fpcap
#id(fpcap.read(0))
#print pcap_header
#把pacp文件头信息写入result.txt
'''
ftxt.write("Pcap文件的包头内容如下： \n")
for key in ['magic_number','version_major','version_minor','thiszone',
            'sigfigs','snaplen','linktype']:
    ftxt.write(key+ " : " + repr(pcap_header[key])+'\n')
'''        
#pcap文件的数据包解析
step = 0
packet_num = 0
packet_num0=0
packet_data = []

pcap_packet_header = {}
i =24

def str_to_hex(strs):

              hex_data =''
              for i in range(len(strs)):
                     tem = ord(strs[i])
                     tem = hex(tem)
                     if len(tem)==3:
                            tem = tem.replace('0x','0x0')
                     tem = tem.replace('0x','')
                     hex_data = hex_data+tem
              return '0x'+hex_data
while(i<size):
      #chu shi hua  dou yao wei 0
      ethtype=None
      ttl=None
      protocol=None
      sip={}
      dip={}
      sport=None
      dport=None
      #数据包头各个字段
      tem=fpcap.read(16)
      pcaphead=PcapHead(tem)
      pcap_packet_header=pcaphead.readhead()
      #求出此包的包长len
    #  packet_len = struct.unpack('I',pcap_packet_header[3])[0]
      packet_len=pcap_packet_header[3]
      data=fpcap.read(packet_len)
      s=data[0:14]         #Ethernet
      eth=Ethernet(s)
      ethtype=eth.readhead()
      if ethtype=='IP':
        tem=data[14:34]
        iphead=IP(tem)
        [ttl,protocol,sip,dip]=iphead.readhead()
        if protocol=='ICMP':
           pass
        elif protocol=='IGMP':
          #fpcap.seek((packet_len-34),1)
           pass
        elif protocol=='TCP'or protocol=='UDP':
          tem = data[34:38]
          tcpudp=Tcpudp(tem)
          [sport,dport]=tcpudp.readhead()
          #fpcap.seek((packet_len-38),1)
        else:
          #fpcap.seek((packet_len-34),1)
           pass
      elif ethtype=='ARP':
        tem=data[14:60]
        arp=ARP(tem)
        [sip,dip]=arp.readhead()
        #fpcap.seek((packet_len-60),1)
      else:
        #fpcap.seek((packet_len-14),1)
        i= i+16+ packet_len
        packet_num0+=1
        continue
        #pass
      #写入此包数据
   #  print pcap_packet_header
    # packet_data.append(fpcap.read(packet_len))
    #  fpcap.seek(packet_len,1)
      i= i+16+ packet_len
      packet_num+=1
      packet_num0+=1
      data=str_to_hex(data)
      s=[{'GMTtime':repr(pcap_packet_header[0]),'MicroTime':repr(pcap_packet_header[1]),\
      'caplen':repr(pcap_packet_header[2]),'len':repr(pcap_packet_header[3]),'ethtype':ethtype,'ttl':ttl,\
      'protocol':protocol,'sip0':sip[0],'sip1':sip[1],'sip2':sip[2],'sip3':sip[3],'dip0':dip[0],'dip1':dip[1],'dip2':dip[2],\
      'dip3':dip[3],'sport':sport,'dport':dport,'data':data}]
      datain=json.dumps(s)
      #print datain
      ftxt.writelines(datain+'\n')
#把pacp文件里的数据包信息写入result.txt
'''for i in range(packet_num):
    #先写每一包的包头
    ftxt.write("这是第"+str(i)+"包数据的包头和数据："+'\n')
    for key in ['GMTtime','MicroTime','caplen','len']:
        ftxt.write(key+' : '+repr(pcap_packet_header[key])+'\n')
    #再写数据部分
    ftxt.write('此包的数据内容'+repr(packet_data[i])+'\n')
ftxt.write('一共有'+str(packet_num)+"包数据"+'\n')
'''      
ftxt.close()
fpcap.close()
print packet_num
print packet_num0