/*
* Network structures & functions
* By Stefano Guerrini
* University of Ferrara - April 2015
*
*
*/
unsigned int networks[100][2];
unsigned int netno=0;

unsigned int getIPv4FromString(char * str){
	unsigned int out[4];
	unsigned int ip=0;
	sscanf(str,"%u.%u.%u.%u",out,out+1,out+2,out+3);
	ip += out[0] << 24;
	ip += out[1] << 16;
	ip += out[2] << 8;
	ip += out[3];
	return ip;
}
//Create mask from CIDR
unsigned int createIPv4Mask(unsigned int mask){
	unsigned int out = 0;
	int i=0;
	for(i=0;i<31;i++)
		out = (i < mask ? ++out : out) << 1;
	return out;
}
void addIPv4Network(char * nw){
	char ip[25];
	unsigned int cidr;
	sscanf(nw,"%[^/]/%u",ip,&cidr);
	networks[netno][0] = getIPv4FromString(ip);
	networks[netno][1] = cidr;
	netno++;
}
int getIPv4MaskFromString(char * cip){
	return(getIPv4Mask(getIPv4FromString(cip)));
}
int getIPv4Mask(unsigned int ip){
	unsigned int  i;
	for(i=0;i<netno;i++)
		if((ip & networks[i][1]) == (networks[i][0] & networks[i][1]))
			return 1;
	return 0;
}

void createLepidaNET(){
	//moved
}

