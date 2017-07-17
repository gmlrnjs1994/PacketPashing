
/*
KITRI BEST OF THE BEST 6TH
CONSULTING PeTrA 
CHO HUI GWON
*/

#include <arpa/inet.h>

#include <pcap.h>
#include <stdio.h>


/*
Header Structure 
*/
struct ether_addr{
        unsigned char ether_addr_octet[6];
};
 
struct ether_header{
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        unsigned short ether_type;
};
 
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
        unsigned int sequence;
        unsigned int acknowledge;
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
	dev = pcap_lookupdev(errbuf);
	
	printf("Device : %s\n", dev);	//	print Interface Device
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
	
	while(1){
		exceptionNum == 0;
		res = pcap_next_ex(handle, &header, &packet);
		printf("Jacked a packet with length of [%d]\n", header->len);
		
		if(res == 0){
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
				ether_head->ether_dhost.ether_addr_octet[0],
				ether_head->ether_dhost.ether_addr_octet[1],
				ether_head->ether_dhost.ether_addr_octet[2],
				ether_head->ether_dhost.ether_addr_octet[3],
				ether_head->ether_dhost.ether_addr_octet[4],
				ether_head->ether_dhost.ether_addr_octet[5]);
	printf("Src Mac Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n",
				ether_head->ether_shost.ether_addr_octet[0],
				ether_head->ether_shost.ether_addr_octet[1],
				ether_head->ether_shost.ether_addr_octet[2],
				ether_head->ether_shost.ether_addr_octet[3],
				ether_head->ether_shost.ether_addr_octet[4],
				ether_head->ether_shost.ether_addr_octet[5]);
}

/*
IP header print Function
*/
int print_ip_header(const unsigned char* data){
	struct ip_header *ip_head;
	ip_head = (struct ip_header*)data;
	if((ip_head->ip_protocol) != 0x06){	//	if( !(tcp))
		exceptionNum == 1;
		return ip_head->ip_header_len*4;
	}
	printf("Src IP Address : %s\n", inet_ntoa(ip_head->ip_srcaddr));
	printf("Dst Ip Address : %s\n", inet_ntoa(ip_head->ip_destaddr));
	
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
