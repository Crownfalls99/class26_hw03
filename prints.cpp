# include "pcap-test.h"

void _printMAC (char* mac_addr)
{
	for (int i = 0; i < 6; i++)
	{
		if ( i > 0 )
			putchar(':');

		printf("%02x", mac_addr[i] & 0xff);
	}
	
	putchar('\n');
	return;
}

void printMAC(char* src_mac_addr, char* dst_mac_addr)
{
	printf("Src MAC\t|\t");
	_printMAC(src_mac_addr);

	printf("Dst MAC\t|\t");
	_printMAC(dst_mac_addr);

	return;
}

void _printIP(char* ip_addr)
{
	for (int i = 0; i < 4; i++)
	{
		if ( i > 0 )
			putchar('.');

		printf("%d", ((int)ip_addr[i]) & 0x00ff);
	}

	putchar('\n');
	return;
}

void printIP(char* src_ip_addr, char* dst_ip_addr)
{
	printf("Src IP\t|\t");
	_printIP(src_ip_addr);

	printf("Dst IP\t|\t");
	_printIP(dst_ip_addr);

	return;
}

void _printPORT(char* port)
{
	printf("%d\n", ((((int)port[0]) & 0xff ) << 8) + ((int)port[1] & 0xff));
	
	return;
}

void printPORT(char* src_port, char* dst_port)
{
	printf("Src Port|\t");
	_printPORT(src_port);

	printf("Dst Port|\t");
	_printPORT(dst_port);

	return;
}


