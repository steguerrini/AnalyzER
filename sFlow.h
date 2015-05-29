/*
sFlow version 5 basic structures
By Stefano Guerrini
University of Ferrara - April 2015
---
This files defines the basic sFlow structures
described in RFC 3176 and in sFlow v5:
https://www.ietf.org/rfc/rfc3176.txt
http://sflow.org/sflow_version_5.txt
---
Those structures are far away to be complete but
we do not need anything else for our analysis.
*/
typedef struct{
        unsigned int version;
        unsigned int IPVersion;
        unsigned int agentIP;
        unsigned int agentID;
        unsigned int sequenceNo;
        unsigned int uptime;
        unsigned int samples;
}sFlowDatagram; //28Bytes = 224bits

typedef struct{
	unsigned int dataFormat;
	unsigned int sampleLen;
}sFlowSampleData;

enum SFsampleTag{
	//enterprise = 0, format = ...
	SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
	SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
	SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
	SFLCOUNTERS_SAMPLE_EXPANDED = 4  /* enterprise = 0 : format = 4 */
};
#define SFsampleType(df)	(ntohl(df->dataFormat) & 0xFFF)

typedef struct{
	unsigned int sequenceNo;
	unsigned int sourceID;
	unsigned int countno;
}sFlowCSample; // Counter sample
typedef struct{
	unsigned int dataFormat;
	unsigned int sampleLen;
}sFlowCSRecordHeader;

typedef struct  {
  unsigned int ifIndex;
  unsigned int ifType;
  unsigned long long ifSpeed;
  unsigned int ifDirection;        /* Derived from MAU MIB (RFC 2668)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  unsigned int ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  unsigned long long ifInOctets;
  unsigned int ifInUcastPkts;
  unsigned int ifInMulticastPkts;
  unsigned int ifInBroadcastPkts;
  unsigned int ifInDiscards;
  unsigned int ifInErrors;
  unsigned int ifInUnknownProtos;
  unsigned long long ifOutOctets;
  unsigned int ifOutUcastPkts;
  unsigned int ifOutMulticastPkts;
  unsigned int ifOutBroadcastPkts;
  unsigned int ifOutDiscards;
  unsigned int ifOutErrors;
  unsigned int ifPromiscuousMode;
} sFlowCSGeneric;

typedef struct{
//	unsigned int dataFormat; //TODO: Create sample header
//	unsigned int sampleLen; //TODO: Create sample header because we can have a counter sample instead of flow sample
	unsigned int sequenceNo;
	unsigned int sourceID; //Class + Index
	unsigned int samplingRate;
	unsigned int samplePool;
	unsigned int droppedPkts;
	unsigned int inidx;
	unsigned int outidx;
	unsigned int flowno;
}sFlowFSample;

typedef struct {
	unsigned int dataFormat;
	unsigned int dataLen;
}sFlowFSRecordHeader;

typedef struct{
	unsigned int proto;
	unsigned int frameLen;
	unsigned int skip; //Payload removed
	unsigned int headerLen;
}sFlowFSRawRecord;

typedef struct {
   unsigned int src_vlan;     /* The 802.1Q VLAN id of incoming frame */
   unsigned int src_priority; /* The 802.1p priority of incoming frame */
   unsigned int dst_vlan;     /* The 802.1Q VLAN id of outgoing frame */
   unsigned int dst_priority; /* The 802.1p priority of outgoing frame */
}sFlowFSExtSwitchRecord;

enum SFFSrecordFormat{
	RAWHEADER = 1,
	EXTSWITCH = 1001
};

#define SIZE_SFLOW_DATAGRAM 28
#define SIZE_SFLOW_SAMPLEDATA 8
#define SIZE_SFLOW_SAMPLE 32
#define SIZE_SFLOW_RECHEADER 8
#define SIZE_SFLOW_RAWRECORD 16
#define SIZE_SFLOW_ESRECORD 16


unsigned int getRecordType(const sFlowFSRecordHeader * srh){
	return (ntohl(srh->dataFormat) &0xFFF);
}
unsigned int getRecordSize(unsigned int dataFormat){
	unsigned int type = dataFormat &0xFFF;
	if(type == RAWHEADER)
		return sizeof(sFlowFSRawRecord);
	else
		return sizeof(sFlowFSExtSwitchRecord);
}
unsigned int getsFlowRecordSize(sFlowFSRecordHeader * srh){
	return (getRecordSize(ntohl(srh->dataFormat)));
}
