/*****************************************************
*	AnalyzER
*	an sFlow Packet Inspector
*	by Stefano Guerrini - University of Ferrara
*	stefano@guerrini.email
* 	This tool has been developed for Lepida spa in 
*	April 2015, working on my undergraduate Thesis.
*	----
*	The tool inspects sFlow packets coming on a 
* 	specific port (e.g. 5600) in order to account the
* 	traffic being exchanged between two hosts.
*	NOTE: This tool does *NOT* account level 2 related
* 	traffic e.g. it does not count ethernet header
*	related traffic. It uses the IPv4 length field to
*	determine the amount of traffic exchanged.
*	----
*	WARNING: THIS TOOL IS STILL IN BETA STATUS
* 	Please...please...let the listening port free from
*	other non-sFlow packets because this tool expects
* 	ONLY sFlow packets on the listening port!
*	----
*  	Libs needed:
*	libpcap
*	libmysql-client
*	---
*	In memoria di mio padre.
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <GeoIP.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql.h>
#include "struct.h"
#include "sFlow.h"
#include <sys/time.h>
#include "network.h"

#define DB_INTERTIME 3600 //Split databases every x seconds
#define SNAPLEN 65535
#define MEAN_TIME 300000 //Number of milliseconds for the mean traffic
#define MEAN_TIME_S 300 //5 minutes log
#define TRANSACTION_QUERIES 50 //MySql Transaction size

pcap_t * handle = NULL; //pcap communication handle
struct pcap_stat pcapstat;
MYSQL * mysql = NULL;
unsigned int procPackets=0; //Total processed packets
unsigned int discPackets=0; //Discarded packets (IPv6)
unsigned long long int discLocBytes=0; //Discarded packets because they come from same AS! This will overflow after about 18000 PB
FILE * statfp = NULL ; //File for stats
GeoIP * geoip = NULL;
unsigned short sqlTran=0; //used for sql transaction
char dbTable[128];

ASData ipToASNum(GeoIP * geoip, unsigned int ips);
unsigned int uipTouASNum(unsigned int ip);

void closeAll(char * error){
	
	if(statfp != NULL)
		fclose(statfp);
	if(handle != NULL)
		pcap_close(handle);
	if(mysql != NULL){
		mysql_query(mysql,"COMMIT;");
		mysql_close(mysql);	
	}	
	if(geoip != NULL)
		GeoIP_delete(geoip);
	if(error != NULL)
		printf("\n%s",error);
	if(handle != NULL)
		pcap_stats(handle,&pcapstat);

	printf("\n\n(Flow) Packet processed:%u\n",procPackets);
	printf("Discarded packet by pcap: %u\n",pcapstat.ps_drop);
	printf("Discarded ipv6 packets:%u\n",discPackets);
	printf("Total local bytes (discarded): %llu (%.2lf GB)\n",discLocBytes,(double)(discLocBytes)/1000000000);
	printf("Analysis ended at: %u\n",time(NULL));

	fflush(stdout);
	fflush(stderr);
	if(error != NULL)
		exit(1);
	exit(0);
}

void inaddrtoIPchar(unsigned int ips, char * out);

inline void insertMySQL(unsigned int srcip, unsigned int dstip, unsigned int bytes){
	char query[1024];
	unsigned int asnumd=0; //DESTINATION ASNUM
	unsigned int asnums=0; //SOURCE ASNUM
	char a[100],b[100];

	if(sqlTran++ == 0)
		mysql_query(mysql,"START TRANSACTION;");

	asnumd=uipTouASNum(dstip);
	asnums=uipTouASNum(srcip);
	if(asnumd == 0) asnumd=31638;
	if(asnums == 0) asnums=31638;
	if(asnumd != asnums){
		if(asnumd != 31638 && asnums != 31638){  //We have remote <-> remote
			inaddrtoIPchar(srcip,a);
			inaddrtoIPchar(dstip,b);
			printf("PEER!! (AS %u) %s <-> %s (AS %u)\n",asnums,a,b,asnumd);
			sprintf(query,"INSERT INTO %s (ASNum,date,traffic_in_peer) VALUES(%u,FROM_UNIXTIME(%u),%u) ON DUPLICATE KEY UPDATE traffic_in_peer=traffic_in_peer+%u",dbTable,asnumd,time(NULL),bytes,bytes);
			mysql_query(mysql,query);
			sprintf(query,"INSERT INTO %s (ASNum,date,traffic_out_peer) VALUES(%u,FROM_UNIXTIME(%u),%u) ON DUPLICATE KEY UPDATE traffic_out_peer=traffic_out_peer+%u",dbTable,asnums,time(NULL),bytes,bytes);
			mysql_query(mysql,query);
		}
		else{ //we have local<->remote
			sprintf(query,"INSERT INTO %s (ASNum,date,traffic_in) VALUES(%u,FROM_UNIXTIME(%u),%u) ON DUPLICATE KEY UPDATE traffic_in=traffic_in+%u",dbTable,asnumd,time(NULL),bytes,bytes);
			mysql_query(mysql,query);
			sprintf(query,"INSERT INTO %s (ASNum,date,traffic_out) VALUES(%u,FROM_UNIXTIME(%u),%u) ON DUPLICATE KEY UPDATE traffic_out=traffic_out+%u",dbTable,asnums,time(NULL),bytes,bytes);
			mysql_query(mysql,query);
		}
	
		if(sqlTran >= TRANSACTION_QUERIES){
			mysql_query(mysql,"COMMIT;");
			sqlTran=0;
		}
	}
	else //we have REMOTE<->REMOTE with the same AS...WTF?!
		discLocBytes+= bytes; 
}
void siginth(int sig){
	printf("\nReceived SIGINT...Wait for connection to close");
	closeAll(NULL);
}

void inaddrtoIP(unsigned int ip , unsigned int * uip){
	uip[0] = (ip >> 24) & 0xFF;
	uip[1] = (ip >> 16) & 0xFF;
	uip[2] = (ip >> 8) & 0xFF;
	uip[3] = (ip) &0xFF;
}
void inaddrtoIPchar(unsigned int ips, char * out){
        unsigned int uip[4];
        inaddrtoIP(ips,uip);
        sprintf(out,"%u.%u.%u.%u",uip[0],uip[1],uip[2],uip[3]);
}

ASData ipToASNum(GeoIP * geoip, unsigned int ips){
        char ipchar[20];
        ASData asdata;
        inaddrtoIPchar(ips,ipchar);
        asdata.rawptr = GeoIP_org_by_name(geoip,ipchar);
//Seems to have some problems here...
        if(asdata.rawptr == NULL){
                asdata.num = 0;
                asdata.name[0]=0;
        }
        else{
                sscanf(asdata.rawptr,"AS%u %s",&asdata.num,asdata.name);
                free(asdata.rawptr);
        }
        return asdata;
}
unsigned int uipTouASNum(unsigned int ip){
	return(ipToASNum(geoip,ip).num);
}	
void printHelp(){
	printf("\nUsage:\n");
	printf("analyzer iface workingdir\n");
	exit(1);
}

//And remember...endianness is everything!
//remember to use ntohl e ntohs whenever you use a member!
int main(int argc, char ** argv){

	//general purposes variables
	unsigned int i=0,j,k;
	//pcap variables
	char dev[] = "eth1";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 net;
	bpf_u_int32 netmask;
	const u_char *packet;
	struct pcap_pkthdr * header;
	int pcapRet;
	
	//sflow structures
	sFlowDatagram * sfd;
	sFlowFSRawRecord * sfrr;
	sFlowFSample * sfs;
	sFlowFSRecordHeader * sfrh;
	sFlowSampleData * sfsd;

	sFlowCSample * sfcs;
	sFlowCSRecordHeader * sfcsh;
	sFlowCSGeneric * sfcsg;

	unsigned int difftime;
	//support struct
	IPHeader *ip; /* The IP header */
	char buf[1024]; //A little temporary buffer for parameter parsing
		
	//mean time traffic size
	TrafficT start;
	TrafficT end;
	start.time=0;
	start.traffic = 0;
	end.time=0;
	end.traffic = 0 ;
	end.traffic_incoming = 0;
	end.traffic_outcoming = 0;
	end.inUnicast = 0;
	end.outUnicast = 0;
	end.inMulticast = 0;
	end.outMulticast = 0;
	end.inBroadcast = 0;
	end.outBroadcast = 0;
	end.sig_traffic = 0;

	unsigned long long meanTraffic=0; 
	
	unsigned int packetSize;
	
	//USAGE
	if(argc < 4){
		printf("\n===Lepida Traffic Anaylzer===\n\tv.0.0.1\nBy Stefano Guerrini\nstefano@guerrini.email\nUsage: %s <listening port> <db table> <stat file>\n",argv[0]);
		closeAll(NULL);
	}

	//install signal handlers
	signal(SIGINT,siginth); //CRTL+C
	signal(SIGTERM,siginth); //kill signal handling.

	createLepidaNET();

	geoip = GeoIP_open("/var/www/analisi/GeoIPASNum.dat", GEOIP_MEMORY_CACHE);
	if(!geoip)
		closeAll("Cannot load geoip");
	mysql = mysql_init(NULL);
	if(!mysql)
		closeAll("Cannot instantiate mysql structure..run out of memory?");
	if(!mysql_real_connect(mysql,"127.0.0.1","studente","studente","tesi",0,NULL,0))
		closeAll("Cannot connect to mysql database");
	mysql_query(mysql,"SET autocommit=0");
	
	strcpy(dbTable,argv[2]);
	//statfp = fopen("/home/studente/prove/analyzer/stat.csv","w"); //TODO: CHECK FOR ERRORS & USER-DEFINED FILE
	statfp = fopen(argv[3],"w"); //TODO: CHECK FOR ERRORS & USER-DEFINED FILE
	if(!statfp)
		closeAll("Could not open stat file.\n");
	fprintf(statfp,"timestamp,ingoing_traffic,outgoing_traffic,inUnicast,outUnicast,inMulticast,outMulticast,inBroadcast,outBroadcast,monitoring_traffic\n");

	//if all went ok..start pcap
	pcap_lookupnet(dev,&net,&netmask,errbuf);
	handle = pcap_open_live(dev,SNAPLEN,1,1000,errbuf);
	if(handle == NULL)
		closeAll("Could not open interface.\n");
		
	//Set filter to get traffic only on port 5600
	sprintf(buf,"port %s",argv[1]);
	if(pcap_compile(handle,&fp,buf,0,net) == -1)
		closeAll("Error occured occured in filter creation\n");
	if(pcap_setfilter(handle,&fp) == -1)
		closeAll("Error while setting filter \n");
		
	printf("Analysis starded at: %u\n",time(NULL));
	//enter main sniff loop
	while(1){
//		if(time(NULL)>= 1429956000) //debug only
//			closeAll(NULL);
		if(pcap_next_ex(handle,&header,&packet)!=1){
			fprintf(stderr,"Pcap returned an error...\n");
			continue;
		}
		//Encapsulation summary: PACKET = [ETH][IPv4][UDP][sFlowHeader][FlowSample1][FlowSample2]...
		ip = (IPHeader*)(packet + SIZE_ETH);
		end.sig_traffic += ntohs(ip->ip_len);
		packet += UDP_PAYLOAD_OFFSET; //skip udp header
		sfd = (sFlowDatagram*)(packet); //the sflow datagram
		
		//collect traffic stats
		packet += SIZE_SFLOW_DATAGRAM;
		
		
		for(j=0;j< ntohl(sfd->samples);j++){ //iterate through the samples
			sfsd = (sFlowSampleData *) (packet);
			packet += SIZE_SFLOW_SAMPLEDATA;

			if(SFsampleType(sfsd) != SFLFLOW_SAMPLE){ //we are interested only on flow samples..
				//We use counter sample to determine the EXACT counter
				if(SFsampleType(sfsd) == SFLCOUNTERS_SAMPLE){
				//Counter Sample Format: [CounterSampleHeader][Counter1][Counter2]...
				//Counter generic format: [CounteRecordHeader][Counter Record]
					sfcs = (sFlowCSample *)(packet);
					sfcsh = (sFlowCSRecordHeader *) (packet + sizeof(sFlowCSample));
					sfcsg = (sFlowCSGeneric * ) (packet + sizeof(sFlowCSample) + sizeof (sFlowCSRecordHeader));
					end.traffic_incoming = be64toh(sfcsg->ifInOctets);
					end.traffic_outcoming = be64toh(sfcsg->ifOutOctets);
					end.inUnicast = ntohl(sfcsg->ifInUcastPkts);
					end.outUnicast = ntohl(sfcsg->ifOutUcastPkts);
					end.inMulticast = ntohl(sfcsg->ifInMulticastPkts);
					end.outMulticast = ntohl(sfcsg->ifOutMulticastPkts);
					end.inBroadcast = ntohl(sfcsg->ifInBroadcastPkts);
					end.outBroadcast = ntohl(sfcsg->ifOutBroadcastPkts);
					
					end.time = ntohl(sfd->uptime)/1000; //time in secondi
					difftime = end.time - start.time;
					//real = end - start perchè il contatore è progressivo
					fprintf(statfp,"%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",time(NULL),8*(end.traffic_incoming-start.traffic_incoming)/difftime,8*(end.traffic_outcoming-start.traffic_outcoming)/difftime,end.inUnicast-start.inUnicast,end.outUnicast-start.outUnicast,end.inMulticast-start.inMulticast,end.outMulticast-start.outMulticast,end.inBroadcast-start.inBroadcast,end.outBroadcast-start.outBroadcast,8*end.sig_traffic/difftime);
					fflush(statfp);
					printf("CSample IN: %lld OUT: %lld \n",be64toh(sfcsg->ifInOctets),be64toh(sfcsg->ifOutOctets));	
					end.sig_traffic = 0;
					start = end;
					
				}

				packet += ntohl(sfsd->sampleLen);
			}
			else{

				//Flow sample format: [FlowSampleHeader][FlowRecord1][FlowRecord2]...
				sfs = (sFlowFSample *)(packet);
				packet +=SIZE_SFLOW_SAMPLE;
				procPackets+=1;
				for(k=0;k < ntohl(sfs->flowno);k++){ //iterate through the flow record of the current sample
					//Flow record format: [FlowRecordHeader][FlowRecord]
					sfrh = (sFlowFSRecordHeader *)(packet);
					packet+=SIZE_SFLOW_RECHEADER;
					if(getRecordType(sfrh) == RAWHEADER){ //we only support raw header (the one in lepida spa network)
						sfrr = (sFlowFSRawRecord*)(packet);
						ip = (IPHeader *)(packet + sizeof(sFlowFSRawRecord) + SIZE_ETH); //our interest is on the IP packet!
						
						if(IP_V(ip) != 4){ //ipv6 packet are not yet supported
							printf("IPv6 Packet discarded!\n");
							discPackets+=1;
						}else{ //Finally we can read what we want!
							packetSize = ntohs(ip->ip_len)*ntohl(sfs->samplingRate);
							insertMySQL(ntohl(ip->ip_src.s_addr),ntohl(ip->ip_dst.s_addr),packetSize);
						}
					}
				packet += ntohl(sfrh->dataLen); //indipendentemente dal tipo di record vado avanti di dataLen
				}
			}
		}
	} //while
	
	return 0;
}
