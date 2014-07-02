

//typedef struct pcap_pkthdr32 {
	// Need to make sure it's in the 32 bit format...
//	unsigned int tv_s;	
//	unsigned int tv_us;
//	unsigned int caplen;	
//	unsigned int len;	
//}PcapPacketHead;


//typedef struct Ip{
//unsigned char pro;//xieyi
//unsigned int Sip;
//unsigned int Dip;
//}Ip_head;

//typedef struct T/U{
//unsigned short Sport;
//unsigned short Dport;
//}TU_head;

//int readpcap(FILE *fp,PcapPacketHead pcap_head);
//int writepcap(FILE *fp,PcapPacketHead pcap_head);
//int readheadIP(FILE *fp,Ip_head ip);
//int writeIP(FILE *fp,IP_head ip);
//int readTU(FILE *fp,TU_head tu);
//int writeTU(FILE *fp,TU_head tu);
typedef struct head_message{
    unsigned int tv_s;	
	unsigned int tv_us;
	unsigned int caplen;	
	unsigned int len;	
   unsigned char pro;//xieyi
   unsigned char Sip0;
 unsigned char Sip1;
 unsigned char Sip2;
 unsigned char Sip3;
   unsigned char Dip0;
unsigned char Dip1;
unsigned char Dip2;
unsigned char Dip3;
   unsigned short Sport;
   unsigned short Dport;
}head;
//int read(FILE *fp,head head_m);
//void write(head head_m);

void Change(unsigned short *pValue);



















