#!/usr/bin/env python
#coding=utf-8
import ujson
import json
import struct

f=open('test.pcap','r')
print f
#fm=ft.seek(0,2)
#print fm
#print f
#string=f.read()
#print string

print f.read(4)
#print Magic
major=f.read(2)
minor=f.read(2)
thiszone=f.read(4)
sigfigs=f.read(4)
snaplen=f.read(4)
linktype=f.read(4)
s='major:'+major+'minor:'+minor+'thiszone:'+thiszone+'sigfigs:'+sigfigs+'snaplen:'+snaplen+'linktype:'+linktype
print s
count=0
'''
print f
fi=open('test.json','w')
while True:
#finally:
 #  if  f:
  #       
   #      break
	if f==fm:
             break
        tv_s=(f.read(4))
        tv_us=(f.read(4))
        caplen=(f.read(4))
        leng=(f.read(4))
        count=count+1
#        f.seek(caplen,1)
        s='a:'+tv_s+'b:'+tv_us+'c:'+caplen+'d:'+leng+'\n'
        print s
        data=json.dumps(s)
        fi.writelines(data)
        break
      '''
f.close()
#fi.close()  
#print count 





