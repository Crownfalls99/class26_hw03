# ifndef PCAP_TEST_H
# define PCAP_TEST_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <stdint.h>
# include <netinet/in.h>
# include <pcap.h>

# endif

typedef struct MAC_HEADER
{
	char dstmac[6];
	char srcmac[6];
	char ethtype[2];
} MAC_h;

typedef struct IPv4_HEADER
{
	char info[12];
	char srcip[4];
	char dstip[4];
} IP_h;

typedef struct TCP_HEADER
{
	char srcport[2];
	char dstport[2];
	char trash[8];
	char len;	
} TCP_h;

void printMAC (char* src_mac_addr, char* dst_mac_addr);
void printIP (char* src_ip_addr, char* dst_ip_addr);
void printPORT (char* src_port, char* dst_port);

