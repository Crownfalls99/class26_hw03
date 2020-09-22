# include "pcap-test.h"

void usage(void)
{
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");

	return;
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		usage();
		exit(1);
	}

	const char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr)
	{
		fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
		exit(1);
	}

	int j = 1;
	while (j <= 10)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0)
			continue;

		if (res == -1 || res == -2)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		int offset = 0;
		MAC_h* info1 = (MAC_h*)malloc(sizeof(MAC_h));
		memcpy(info1, packet + offset, sizeof(MAC_h));

		offset += sizeof(MAC_h);
		IP_h* info2 = (IP_h*)malloc(sizeof(IP_h));
		memcpy(info2, packet + offset, sizeof(IP_h));

		if (((info2->info[0]>>4) != 0x04) && (info2->info[9] != 0x06))
		{
			free(info1);
			free(info2);
			continue;
		}

		offset += ( (int)(info2->info[0]) & 0x000f ) << 2;
		TCP_h* info3 = (TCP_h*)malloc(sizeof(TCP_h));
		memcpy(info3, packet + offset, sizeof(TCP_h));

		offset += ( (int)(info3->len) & 0x00f0 ) >> 2;

		printf("*** Packet No.%02d ***\n", j);
		printMAC(info1->srcmac, info1->dstmac);
		printIP(info2->srcip, info2->dstip);
		printPORT(info3->srcport, info3->dstport);

		printf("Payload\t|\t");
		for(int i = 0; i < 16; i++)
		{
			if ( *(packet + offset + i) == '\0')
				break;
			
			printf("%02x ", (int)( *(packet + offset + i) ) & 0x00ff );
		}

		printf("\n\n");
		j++;

		free(info1);
		free(info2);
		free(info3);
	}

	pcap_close(handle);
	return 0;
}


