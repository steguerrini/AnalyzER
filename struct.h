/*
* sFlow analyzER support structures
* By Stefano Guerrini
* University of Ferrara - April 2015
* --- 
* This files defines the support structures
* needed by the analyzer tool. 
* ---
*/

	/* Ethernet addresses are 6 bytes */
	#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	typedef struct {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	}EthHeader;

	/* IP header */
	typedef struct {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	}IPHeader;
	typedef struct{
		unsigned int ip_vtcfl;
		u_short ip_len;
		u_char ip_nhdr;
		u_char ip_hop; //TODO: Change to HopLimit
		unsigned int ip_src[4];
		unsigned int ip_dst[4];
	}IPv6Header;
	

	typedef struct {
		unsigned short port_src,port_dst;
		unsigned short len;
		unsigned short sum;
	}UDPHeader;

	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	#define SIZE_ETH 14
	#define SIZE_IP 20
	#define SIZE_IP6 40
	#define SIZE_UDP 8
	#define UDP_PAYLOAD_OFFSET SIZE_ETH+SIZE_IP+SIZE_UDP

	typedef struct {
		char * rawptr;
		unsigned int num; //We use a 4bytes integer 
		char name[256];
	}ASData;

	typedef struct {
		unsigned long long traffic;
		unsigned long long  traffic_incoming; 
		unsigned long long  traffic_outcoming;
		unsigned int inUnicast;
		unsigned int outUnicast;

		unsigned int inMulticast;
		unsigned int outMulticast;
		unsigned int inBroadcast;
		unsigned int outBroadcast;
		unsigned long long sig_traffic; //traffico di segnalazione
		time_t time;
	}TrafficT;
