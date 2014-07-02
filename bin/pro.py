EtherType = {'0x0600':'XEROX NS IDP',
    '0x0660':'DLOG',
    '0x0661':'DLOG',
    '0x0800':'IP',
    '0x0801':'X.75',
    '0x0802':'NBS',
    '0x0803':'ECMA',
    '0x0804':'Chaosnet',
    '0x0805':'X.25',
    '0x0806':'ARP',
    '0x0808':'Frame Relay ARP',
    '0x6559':'Raw Frame Relay',
    '0x8035':'RARP',
    '0x8037':'Novell Netware IPX',
    '0x809B':'Ether Talk',
    '0x80d5':'IBM SNA Service over Ethernet',
    '0x80f3':'AARP',
    '0x8100':'EAPS',
    '0x8137':'IPX',
    '0x814c':'SNMP',
    '0x86dd':'IPv6',
    '0x880b':'PPP',
    '0x880c':'GSMP',
    '0x8847':'MPLS(unicase)',
    '0x8848':'MPLS(multicast)',
    '0x8863':'PPPoE(Discovery stage)',
    '0x8864':'PPPoE(ppp session stage)',
    '0x88bb':'LWAPP',
    '0x88cc':'LLDP',
    '0x8e88':'EAP over LAN',
    '0x888e':'802.1X Authentication',
    '0x9000':'Loopback',
    '0x9100':'VLAN Tag PI',
    '0x9200':'VLAN Tag PI',
    '0xffff':'Reservations',
    '0x2050':'null'
    }

IpType ={'0x01':'ICMP',
         '0x02':'IGMP',
         '0x06':'TCP',
         '0x11':'UDP'
         } 
# you dai wan shan qi ta xie yi
class Protocol(object):

       def __init__(self):

              pass
# transform like '\x01\x0e\0xb0' to '0x010eb0'

       def str_to_hex(self,strs):

              hex_data =''
              for i in range(len(strs)):
                     tem = ord(strs[i])
                     tem = hex(tem)
                     if len(tem)==3:
                            tem = tem.replace('0x','0x0')
                     tem = tem.replace('0x','')
                     hex_data = hex_data+tem
              return '0x'+hex_data
class PcapHead(Protocol):
  def __init__(self,datastr):
      self.datastr=datastr
      self.GMTtime =None
      self.MicroTime =None
      self.caplen=None
      self.leng =None

  def exchange(self,datastr):
      tem0=datastr[0:1]
      tem1=datastr[1:2]
      tem2=datastr[2:3]
      tem3=datastr[3:4]
      s=tem3+tem2+tem1+tem0
      return s

  def readhead(self):
      s=self.exchange(self.datastr[0:4])
      tem= self.str_to_hex(s)
      self.GMTtime =int(tem,16)
      s=self.exchange(self.datastr[4:8])
      tem= self.str_to_hex(s)
      self.MicroTime = int(tem,16)
      s=self.exchange(self.datastr[8:12])
      tem= self.str_to_hex(s)
      self.caplen= int(tem,16)
      s=self.exchange(self.datastr[12:])
      tem= self.str_to_hex(s)
      self.leng =int(tem,16)
      return[self.GMTtime,self.MicroTime,self.caplen,self.leng]

class Ethernet(Protocol):

       def __init__(self,datastr=None):
            self.datastr=datastr
            self.type=None

       def readhead(self):
            un=self.str_to_hex(self.datastr[12:14])
            tem=int(un,16)
            if tem<=1500:
                self.type='802.3'
            elif tem>=1536:
                self.type=EtherType[un]
            return self.type

class IP(Protocol):
       def __init__(self,datastr=None):
            self.datastr=datastr
            self.ttl=None
            self.protocol=None
            self.sip={}
            self.dip={}
       def readhead(self):
            tem=self.str_to_hex(self.datastr[8:9])
            self.ttl=int(tem,16)
            tem=self.str_to_hex(self.datastr[9:10])
            self.protocol=IpType[tem]
            tem=self.str_to_hex(self.datastr[12:13])
            self.sip[0]=int(tem,16)
            tem=self.str_to_hex(self.datastr[13:14])
            self.sip[1]=int(tem,16)
            tem=self.str_to_hex(self.datastr[14:15])
            self.sip[2]=int(tem,16)
            tem=self.str_to_hex(self.datastr[15:16])
            self.sip[3]=int(tem,16)
            tem=self.str_to_hex(self.datastr[16:17])
            self.dip[0]=int(tem,16)
            tem=self.str_to_hex(self.datastr[17:18])
            self.dip[1]=int(tem,16)
            tem=self.str_to_hex(self.datastr[18:19])
            self.dip[2]=int(tem,16)
            tem=self.str_to_hex(self.datastr[19:])
            self.dip[3]=int(tem,16)
            return [self.ttl,self.protocol,self.sip,self.dip]
class ARP(Protocol):
     def __init__(self,datastr=None):
      self.datastr=datastr
      self.sip={}
      self.dip={}
     def readhead(self):
      tem=self.str_to_hex(self.datastr[14:15])
      self.sip[0]=int(tem,16)
      tem=self.str_to_hex(self.datastr[15:16])
      self.sip[1]=int(tem,16)
      tem=self.str_to_hex(self.datastr[16:17])
      self.sip[2]=int(tem,16)
      tem=self.str_to_hex(self.datastr[17:18])
      self.sip[3]=int(tem,16)
      tem=self.str_to_hex(self.datastr[24:25])
      self.dip[0]=int(tem,16)
      tem=self.str_to_hex(self.datastr[25:26])
      self.dip[1]=int(tem,16)
      tem=self.str_to_hex(self.datastr[26:27])
      self.dip[2]=int(tem,16)
      tem=self.str_to_hex(self.datastr[27:28])
      self.dip[3]=int(tem,16)
      return [self.sip,self.dip]
class ICMP(Protocol):
     def __init__(self,datastr=None):
      # self.datastr=datastr
      pass
class IGMP(Protocol):
     def __init__(self,datastr=None):
      pass

class Tcpudp(Protocol):
     def __init__(self,datastr=None):
      self.datastr=datastr
      self.spt=None
      self.dpt=None
     def readhead(self):
      tem=self.str_to_hex(self.datastr[0:2])
      self.spt=int(tem,16)
      tem=self.str_to_hex(self.datastr[2:4])
      self.dpt=int(tem,16)
      return [self.spt,self.dpt]
