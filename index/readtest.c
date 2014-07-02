#include<stdio.h>
#include <stdlib.h>
#include "read.h"
#include<time.h>
//#include<sys/types.h>
//#include<unistd.h>
typedef struct pcap_hdr{
    unsigned int magic;
    unsigned short major;
    unsigned short minor;
    unsigned int thiszone;
    unsigned int sigfigs;
     int snaplen;
    unsigned int linktype;
}PcapHead;

//typedef struct pcap_pkthdr32 {
	// Need to make sure it's in the 32 bit format...
//	unsigned int tv_s;	/* time stamp */
//	unsigned int tv_us;
//	unsigned int caplen;	/* length of portion present */
//	unsigned int len;	/* length this packet (off wire) */
//}PcapPacketHead;

/*int main()
{
  //unsigned char filename = "test.pcap";
  PcapPacketHead pcap_packethead;
  FILE *fp;
  int i;
  
  fp=fopen("test.pcap","r");
  if(fp==NULL)
{
 perror("Open file textfile");
 exit(1);
 }
  if(fread(&buffer[0],sizeof(unsigned int),1,fp)==0)
    exit(1);
  int j;
  for(j=0;j<3;j++)
  {
  if((i=fseek(fp,4,SEEK_CUR))<0)
  {
    perror("fseek error");
    return 0;
  }
  else
  {
  if(fread(&buffer[j+1],sizeof(unsigned int),1,fp)==0)
     exit(1);
  }
  }
  pcap_packethead.tv_s=buffer[0];
  pcap_packethead.tv_us=buffer[1];
  pcap_packethead.caplen=buffer[2];
  pcap_packethead.len=buffer[3];
  int n;
 for( n=0;n<4;n++)
  printf("%u\n",buffer[n]);
}*/
void Change(unsigned short *pValue)
{
     unsigned char c=0, *pByte=(unsigned short*)pValue;
     c=pByte[0];   pByte[0]=pByte[1];   pByte[1]=c;
     
}
int main()
{
	clock_t start, finish;
	float time=0;
	start=clock();
	FILE *fp;
	PcapHead pcap_head;
	head head_m,head_temp;
	fp=fopen("dump.pcap","r");
    if(fp==NULL)
    {
     perror("Open file textfile");
     exit(1);
    }
	if(fread(&pcap_head.magic,sizeof(unsigned int),1,fp)==0)
	    exit(1);
	if(fread(&pcap_head.major,sizeof(unsigned short),1,fp)==0)
	    exit(1);
	if(fread(&pcap_head.minor,sizeof(unsigned short),1,fp)==0)
 	    exit(1);
	if(fread(&pcap_head.thiszone,sizeof(unsigned int),1,fp)==0)
	    exit(1);
	if(fread(&pcap_head.sigfigs,sizeof(unsigned int),1,fp)==0)
	    exit(1);
	if(fread(&pcap_head.snaplen,sizeof( int),1,fp)==0)
	    exit(1);
	if(fread(&pcap_head.linktype,sizeof(unsigned int),1,fp)==0)
	    exit(1);

printf("%x\n%x\n%x\n%x\n%x\n%x\n%x\n",
pcap_head.magic,pcap_head.major,pcap_head.minor,pcap_head.thiszone,
pcap_head.sigfigs,pcap_head.snaplen,pcap_head.linktype);
int count=0;
FILE *fq;
unsigned int step=0;
fq=fopen("temp.csv","w");
if(fq==NULL)
{
 perror("Open file error");
 exit(1);
 }
for(;!feof(fp);count++)
{
//if(fp==EOF) break;
//if(read(fp,head_m)==0) break;
    if(fread(&head_m.tv_s,sizeof(unsigned int),1,fp)==0)
    break;
	if(fread(&head_m.tv_us,sizeof(unsigned int),1,fp)==0)
	break;
	if(fread(&head_m.caplen,sizeof(unsigned int),1,fp)==0)
	break;
	if(fread(&head_m.len,sizeof(unsigned int),1,fp)==0)
	break;
//read ip
   fseek(fp,23,SEEK_CUR);
	if(fread(&head_m.pro,sizeof(unsigned char),1,fp)==0)
   return 0;
 	fseek(fp,2,SEEK_CUR);
  	if(fread(&head_m.Sip0,sizeof(unsigned char),1,fp)==0)
  	return 0;
	if(fread(&head_m.Sip1,sizeof(unsigned char),1,fp)==0)
  	return 0;
	if(fread(&head_m.Sip2,sizeof(unsigned char),1,fp)==0)
  	return 0;
	if(fread(&head_m.Sip3,sizeof(unsigned char),1,fp)==0)
  	return 0;
  	if(fread(&head_m.Dip0,sizeof(unsigned char),1,fp)==0)
    return 0;
	if(fread(&head_m.Dip1,sizeof(unsigned char),1,fp)==0)
    return 0;
	if(fread(&head_m.Dip2,sizeof(unsigned char),1,fp)==0)
    return 0;
	if(fread(&head_m.Dip3,sizeof(unsigned char),1,fp)==0)
    return 0;
    //read TCP/UDP
 	if(fread(&head_m.Sport,sizeof(unsigned short),1,fp)==0)
  	return 0;
    Change(&head_m.Sport);
	if(fread(&head_m.Dport,sizeof(unsigned short),1,fp)==0)
    return 0;
    Change(&head_m.Dport);
// head_temp=head_m;
fprintf(fq,"%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",head_m.tv_s,head_m.tv_us,head_m.caplen,head_m.len,
head_m.pro,head_m.Sip0,head_m.Sip1,head_m.Sip2,head_m.Sip3,head_m.Dip0,
head_m.Dip1,head_m.Dip2,head_m.Dip3,head_m.Sport,head_m.Dport);
//write(head_m);
step=head_m.caplen-38;
fseek(fp,step,SEEK_CUR);
//if(fp==EOF) break;
}
printf("%d\n",count);
fclose(fp);
fclose(fq);
finish=clock();
//printf("%d\n",CLOCKS_PER_SEC);
time=((float)(finish-start)/CLOCKS_PER_SEC);
printf("%f s\n",time);
}

