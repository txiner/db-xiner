#include<stdio.h>
#include <stdlib.h>
#include<read.h>

/*int readpcap(FILE *fp,PcapPacketHead pcap_head)
{
}

int writepcap(FILE *fp,PcapPacketHead pcap_head)

int readheadIP(FILE *fp,Ip_head ip)
{
  if(fp==EOF)
{return 0;}
  fseek(fp,23,SEEK_CUR);
  if(fread(ip.pro,sizeof(unsigned char),1,fp)==0)
    return 0;
  fseek(fp,2,SEEK_CUR);
  if(fread(ip.Sip,sizeof(unsigned int),1,fp)==0)
   return 0;
  if(fread(ip.Dip,sizeof(unsigned int),1,fp)==0)
    return 0;
  
  return ip;
}

int readTU(FILE *fp,TU_head tu)
{
 if(fp==EOF)
 {return 0;}
if(fread(tu.Sport,sizeof(unsigned short),1,fp)==0)
   return 0;
  if(fread(tu.Dport,sizeof(unsigned short),1,fp)==0)
   return 0;
return tu;
}

int writeIP(FILE *fp,IP_head ip)


int writeTU(FILE *fp,TU_head tu)*/

/*int read(FILE *fp,head head_m)
{   //read packethead
    if(fread(&head_m.tv_s,sizeof(unsigned int),1,fp)==0)
    return 0;
	if(fread(&head_m.tv_us,sizeof(unsigned int),1,fp)==0)
	return 0;
	if(fread(&head_m.caplen,sizeof(unsigned int),1,fp)==0)
	return 0;
	if(fread(&head_m.len,sizeof(unsigned int),1,fp)==0)
	return 0;
    //read ip
 //   fseek(fp,23,SEEK_CUR);
 // 	if(fread(&head_m.pro,sizeof(unsigned char),1,fp)==0)
 //   return 0;
 // 	fseek(fp,2,SEEK_CUR);
//  	if(fread(&head_m.Sip,sizeof(unsigned int),1,fp)==0)
//  	return 0;
//  	if(fread(&head_m.Dip,sizeof(unsigned int),1,fp)==0)
//    return 0;
    //read TCP/UDP
// 	if(fread(&head_m.Sport,sizeof(unsigned short),1,fp)==0)
//  	return 0;
//	if(fread(&head_m.Dport,sizeof(unsigned short),1,fp)==0)
//    return 0;
   return 1;*/
}
/*void write(head head_m)
{
printf("%x,%x,%x,%x\n"head_m.tv_s,head_m.tv_us,head_m.caplen,head_m.len);
}
*/
void Change(unsigned short *pValue)
{
     unsigned char c=0, *pByte=(unsigned short*)pValue;
     c=pByte[0];   pByte[0]=pByte[1];   pByte[1]=c;
     
}






