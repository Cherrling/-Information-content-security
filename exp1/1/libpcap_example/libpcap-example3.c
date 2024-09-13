#include <time.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


#define ON		1
#define OFF		0
#define OPTNUM		8
#define TIME_SIZE 	99


char start_time[TIME_SIZE];
char end_time[TIME_SIZE];
int opt[OPTNUM];
char mac[50][18];



enum
{
	ETHER,
	ARP,
	IP,
	TCP,
	UDP,
	ICMP,
	DUMP,
	ALL
};


pcap_t* pd;
int linkhdrlen;

int mac_num = 0;
int ip_num = 0;
int arp_num = 0;
int unknown_num =0;
int icmp_num = 0;
int tcp_num = 0;
int udp_num = 0;
int other_num = 0;
int icmp_redirect = 0;
int icmp_unreachable = 0;
int m = OFF;




void getNowTime(char *nowTime)
{
	char acYear[5] = {0};
	char acMonth[5] = {0};
	char acDay[5] = {0};
	char acHour[5] = {0};
	char acMin[5] = {0};
	char acSec[5] = {0};

	time_t now;
	struct tm* timenow;

	time(&now);
	timenow = localtime(&now);

	strftime(acYear,sizeof(acYear),"%Y",timenow);
	strftime(acMonth,sizeof(acMonth),"%m",timenow);
	strftime(acDay,sizeof(acDay),"%d",timenow);
	strftime(acHour,sizeof(acHour),"%H",timenow);
	strftime(acMin,sizeof(acMin),"%M",timenow);
	strftime(acSec,sizeof(acSec),"%S",timenow);

	strncat(nowTime, acYear, 4);
	strcat(nowTime, "Äê");
	strncat(nowTime, acMonth, 2);
	strcat(nowTime, "ÔÂ");
	strncat(nowTime, acDay, 2);
	strcat(nowTime, "ÈÕ ");
	strncat(nowTime, acHour, 2);
	strcat(nowTime, ":");
	strncat(nowTime, acMin, 2);
	strcat(nowTime, ":");
	strncat(nowTime, acSec, 2);
	strcat(nowTime, "\n");

	return ;
}





/*
 * char *ip_ftoa(int flag)
 * function: change 1~3 of ip->ip_off to string
 * return: string
 */
char *ip_ftoa(int flag)
{
	static int f[] = {'R', 'D', 'M'};
	static char str[17];
	u_int mask = 0x8000;
	int i;

	for(i = 0; i < 3; i++)
	{
		if(((flag << i) & mask) != 0)
		{
			str[i] = f[i];
		}
		else
		{
			str[i] = '0';
		}
	}
	str[i] = '\0';

	return str;

}





/*
 * char *ip_ttoa(int flag)
 * function:change ip->ip_tos to string
 * return:string
 */
char *ip_ttoa(int flag)
{
	static int f[] = {'1', '1','1', 'D', 'T', 'R', 'C', 'X'};
	static char str[17];
	u_int mask = 0x80;

	int i;

	for(i = 0; i < 8; i++)
	{
		if(((flag << i) & mask) != 0)
		{
			str[i] = f[i];
		}
		else
		{
			str[i] = '0';
		}
	}
	str[i] = '\0';

	return str;

}






void print_ip(struct ip *ip)
{
	printf("\nProtocol:IP\n");
	printf("|------------------------------------------------------------------------------------|\n");
	printf("| IV:%1u | HL: %2u | TOS:%8s | Total_len: %10u |\n", ip->ip_v, ip->ip_hl, ip_ttoa(ip->ip_tos), ntohs(ip->ip_len));
	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Identifier:%5u | Flag(R D M):%3s | Off_set:%5u |\n", ntohs(ip->ip_id), ip_ftoa(ntohs(ip->ip_off)), ntohs(ip->ip_off & IP_OFFMASK));            //IP_OFFMASK = 0x1fff
	printf("|------------------------------------------------------------------------------------|\n");
	printf("| TTL:%3u | Pro:%3u | Header checksum: %5u |\n", ip->ip_ttl, ip->ip_p, ntohs(ip->ip_sum));
	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Soure IP Address: %15s |\n", inet_ntoa(*(struct in_addr*)&(ip->ip_src)));
	printf("| Destination IP Address:%15s |\n", inet_ntoa(*(struct in_addr *)&(ip->ip_dst)));
	printf("|------------------------------------------------------------------------------------|\n");

}





pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
    bpf_u_int32  srcip, netmask;
    struct bpf_program  bpf;

    // If no network interface (device) is specfied, get the first one.
    if (!*device && !(device = pcap_lookupdev(errbuf)))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }

    printf("dev name: %s\n", device);
    // Open the device for live capture, as opposed to reading a packet
    // capture file.
    if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0)
    {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    char *net;
    char *mask;

    struct in_addr addr;

    addr.s_addr = srcip;
    net = inet_ntoa(addr);

    if(!net)
    {
	perror("inet_ntoa() ip error");
	exit(1);
    }

    printf("ip: %s\n", net);

    addr.s_addr = netmask;
    mask = inet_ntoa(addr);

    if(!mask)
    {
	perror("inet_ntoa() sub mask error");
	exit(1);
    }
    printf("sub mask: %s\n\n", mask);

    // Convert the packet filter epxression into a packet
    // filter binary.
    if (pcap_compile(pd, &bpf, (char*)bpfstr, 0, netmask))
    {
        printf("pcap_compile(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    // Assign the packet filter to the given libpcap socket.
    if (pcap_setfilter(pd, &bpf) < 0)
    {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    return pd;
}





void capture_loop(pcap_t* pd, int packets, pcap_handler func)
{
    int linktype;

    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(pd)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(pd));
        return;
    }

    // Set the datalink layer header size.
    switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;

    case DLT_EN10MB:
        linkhdrlen = 14;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;

    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }

    // Start capturing packets.
    if (pcap_loop(pd, packets, func, 0) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pd));
}





/*
 * char *mac_ntoa(u_char *d)
 * fucntion:change mac to string
 * return: string
 */
char *mac_ntoa(u_char *d)
{
	static char str[50];

	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

	return str;
}





/*
 * char *tcp_ftoa(int flag)
 * function:
 * return: string
 */
char *tcp_ftoa(int flag)
{
	static int f[] = {
		'U',
		'A',
		'P',
		'R',
		'S',
		'F'
	};

	static char str[17];
	u_int mask = 1 << 5; //0x20;
	int i;

	for(i = 0; i < 6; i++)
	{
		if(((flag << i) & mask) != 0)
		{
			str[i] = f[i];
		}
		else
		{
			str[i] = '0';
		}
	}

	str[i] = '\0';

	return str;
}





/*
 * void print_tcp(struct tcphdr *tcp)
 * function: display tcp header information
 * return: none
 */
void print_tcp(struct tcphdr *tcp)
{
	printf("\nProtocol:TCP\n");

	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Source Port: %5u | Destination Port: %5u |\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));

	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Seq_num: %10lu |\n", (u_long)ntohl(tcp->th_seq));

	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Ack_numr: %10lu |\n", (u_long)ntohl(tcp->th_ack));

	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Off_len: %2u | Reserved | F:%6s | Win_size: %5u |\n", tcp->th_off, tcp_ftoa(tcp->th_flags), ntohs(tcp->th_win));

	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Checksum: %5u | Urg_pointer: %5u |\n", ntohs(tcp->th_sum), ntohs(tcp->th_urp));
	printf("|------------------------------------------------------------------------------------|\n");
}





/*
 * void print_udp(struct udphdr* udp)
 * function: display udp header
 * return:none
 */
void print_udp(struct udphdr *udp)
{
	printf("\nProtocol: UDP\n");

	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Source Port: %5u | Destination Port: %5u |\n",ntohs(udp->uh_sport), (udp->uh_dport));

	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Length:%5u | Checksum: %5u |\n", ntohs(udp->uh_ulen), ntohs(udp->uh_sum));
	printf("|------------------------------------------------------------------------------------|\n");
}





/*
 *void print_icmp(struct icmp* icmp)
 * function:display icmp header information
 * return: none
 */
void print_icmp(struct icmp *icmp)
{
	static char *type_name[] = {
		"Echo Reply",
		"Undefine",
		"Undefine",
		"Destination Unreachable",
		"Source Quench",
		"Redirect(change route)",
		"Undefine",
		"Undefine",
		"Echo Reqest",
		"Undefine",
		"Undefine",
		"Timeout",
		"Parameter Problem",
		"Timestamp Request",
		"Timestamp Reply",
		"Inforamation Request",
		"Information Reply",
		"Address Mask Request",
		"Address Mask Reply",
		"Unknown"
	};

	int type = icmp->icmp_type;

	if(type < 0 || type >18)
	{
		type = 19;
	}
	if(3 == type)
		icmp_unreachable++;
	if(5 == type)
		icmp_redirect++;
	printf("\nProtocol:ICMP ----- %s \n", type_name[type]);

	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Type:%3u | Code:%3u | CheckSum:%5u |\n", icmp->icmp_type, icmp->icmp_code, ntohs(icmp->icmp_cksum));
	printf("|------------------------------------------------------------------------------------|\n");

	if(icmp->icmp_type == 0 || icmp->icmp_type == 8)
	{
		printf("| Identification: %5u | Seq_num %5u |\n", ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
		printf("|------------------------------------------------------------------------------------|\n");
	}
	else if(icmp->icmp_type == 3)
	{
		if(icmp->icmp_code == 4)
		{
			printf("| void  %5u | Next_mtu %5u |\n", ntohs(icmp->icmp_pmvoid), ntohs(icmp->icmp_nextmtu));
			printf("|--------------------------------------------------------------------------------|\n");

		}
		else
		{
			printf("| Unused %10u |\n", (unsigned int)ntohl(icmp->icmp_void));
			printf("|--------------------------------------------------------------------------------|\n");
		}
	}
	else if(icmp->icmp_type == 5)
	{
		printf("| Router IP Address: %15s |\n", inet_ntoa(*(struct in_addr*)&(icmp->icmp_gwaddr)));
		printf("|------------------------------------------------------------------------------------|\n");
	}
	else if(icmp->icmp_type == 11)
	{
		printf("| Unused: %10lu |\n", (u_long)ntohl(icmp->icmp_void));
		printf("|------------------------------------------------------------------------------------|\n");
	}

	if(icmp->icmp_type == 3 || icmp->icmp_type == 5 || icmp->icmp_type == 11)
	{
		print_ip((struct ip*)(((char *)icmp) + 8));
	}

}





/*
 *void print_arp(struct ether_arp *arp);
 * function: display arp information
 * return:none
 */
void print_arp(struct ether_arp *arp)
{
	static char *arp_operation[] =
	{
		"Undefine",
		"(ARP Request)",
		"(ARP Reply)",
		"(RARP Request)",
		"(RARP Reply)"
	};

	int op = ntohs(arp->ea_hdr.ar_op);

	if(op <= 0 || op > 5)
	{
		op = 0;
	}

	printf("\nProtocol:ARP\n");
	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Hardaddr Type: %2u %-11s | Protocol: 0x%04x %-9s |\n",
		 ntohs(arp->ea_hdr.ar_hrd),
		(ntohs(arp->ea_hdr.ar_hrd) == ARPHRD_ETHER) ? "(ETHERNET)":"( NOT OTHER)",
		 ntohs(arp->ea_hdr.ar_pro),
		 (ntohs(arp->ea_hdr.ar_pro) == ETHERTYPE_IP) ? "(IP)": "(NOT IP)");
	printf("|------------------------------------------------------------------------------------|\n");

	printf("| MAC addrlen:%3u | Protocol Addrlen %2u | op: %4d %16s |\n",
		arp->ea_hdr.ar_hln, arp->ea_hdr.ar_pln, ntohs(arp->ea_hdr.ar_op), arp_operation[op]);
	printf("|------------------------------------------------------------------------------------|\n");

	printf("| Sourc MAC address %17s |\n", mac_ntoa(arp->arp_sha));
	printf("-------------------------------------------------------------------------------------|\n");
	printf("| Destination MAC address %17s |\n", mac_ntoa(arp->arp_tha));
	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Source IP address %15s |\n", inet_ntoa(*(struct in_addr *)&arp->arp_spa));
	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Destination IP address %15s |\n", inet_ntoa(*(struct in_addr *)&arp->arp_tha));
	printf("|------------------------------------------------------------------------------------|\n");


}





/*
 * void print_ethernet(struct ether_header *eth)
 * function: disaplay ethernet header
 * return :none
 */
void print_ethernet(struct ether_header* eth)
{
	int type = ntohs(eth->ether_type);

	if(type <= 1500)
	{
		printf("IEEE 802.3 Ethernet Frame:\n");
	}
	else
	{
		printf("\nEthernet Frame:\n");
	}

	printf("|------------------------------------------------------------------------------------|\n");
	printf("| Destination MAC address: %17s |\n", mac_ntoa(eth->ether_dhost));
	printf("| Source MAC address: %17s      |\n", mac_ntoa(eth->ether_shost));
	printf("|------------------------------------------------------------------------------------|\n");

	if(type < 1500)
	{
		printf("| length: %5u   |\n", type);
		printf("|------------------------------------------------------------------------------------|\n");
	}
	else
	{
		printf("| Ethernet Type: 0x%04x  |\n", type);
		if(type == 0X0200)
		{
			printf("| Ethernet Type: xerox PUP |\n");
			printf("|------------------------------------------------------------------------------------|\n");
		}
		else if(type == ETHERTYPE_IP)                      //0x0800
		{
			printf("| Ethernet Type: IP |\n");
			printf("|------------------------------------------------------------------------------------|\n");
		}
		else if(type == ETHERTYPE_ARP)                      //0x0806
		{
			printf("| Ethernet Type:arp |\n");
			printf("|------------------------------------------------------------------------------------|\n");
		}
		else if(type == ETHERTYPE_REVARP)                  //0X8035
		{
			printf("| Ethernet Type: REVARP |\n");
			printf("|------------------------------------------------------------------------------------|\n");
		}
		else
		{
			printf("| Ethernet Type: unknown |\n");
			printf("|------------------------------------------------------------------------------------|\n");

		}
	}

}





/*
 * void dump_packet(unsigned char *buff, int len)
 * function: display data from ethernet frame
 * return: none
 */
void dump_packet(unsigned char * buff, int len)
{
	int i,j;

	printf("\nFrame Dump: \n");

	for(i = 0; i < len; i += 16)
	{
		for(j = i; j < i + 16 && j < len; j++)
		{
			printf("%02x", buff[j]);

			if(j % 2 == 1)
			{
				printf(" ");
			}
		}

		if((j == len) && (len % 16 != 0))
		{
			for(j = 0; j < 40 - (len % 16) * 2.5; j++)
			{
				printf(" ");
			}
			printf(";");
		}

		for(j = i; j < i + 16 && j < len; j++)
		{
			if((buff[j] >= 0x20) && (buff[j] <= 0x7e))
			{
				putchar(buff[j]);

			}
			else
			{
				printf(".");
			}
		}
		printf("\n");
	}
}





void parse_packet(u_char *user, struct pcap_pkthdr *packethdr,
                  u_char *packetptr)
{
	struct ip* iphdr;
    	struct icmphdr* icmphdr;
    	struct tcphdr* tcphdr;
    	struct udphdr* udphdr;
    	struct ether_header *eptr;

    	char iphdrInfo[256], srcip[256], dstip[256];
    	unsigned short id, seq;
	int i, flag;

	eptr = (struct ether_header *)packetptr;

	//
	flag = 0;

	for(i = 0; i<mac_num; i++)
	{
		if(0 == strcmp(mac[i], mac_ntoa(eptr->ether_dhost)))
		{
			flag = 1;
			break;
		}
	}

	if(0 == flag)   /* find new device */
	{
		printf("New mac address found:%s\n", mac_ntoa(eptr->ether_dhost));
		strcpy(mac[mac_num], (char *)mac_ntoa(eptr->ether_dhost));

		mac_num ++;
	}


	flag = 0;

	for(i = 0; i<mac_num; i++)
	{
		if(0 == strcmp(mac[i], mac_ntoa(eptr->ether_shost)))
		{
			flag = 1;
			break;
		}
	}

	if(0 == flag)   /* find new device */
	{
		printf("New mac address found:%s\n", mac_ntoa(eptr->ether_shost));
		strcpy(mac[mac_num], (char *)mac_ntoa(eptr->ether_shost));

		mac_num ++;
	}
	//

    	if(opt[ETHER] == ON)
    		print_ethernet((struct ether_header*)packetptr);

    	if(opt[DUMP] == ON)
    		dump_packet(packetptr,packethdr->len);

    	packetptr += linkhdrlen;


    	if(ntohs(eptr->ether_type) == ETHERTYPE_ARP)
    	{
		arp_num++;
		if(ON == opt[ARP])
			print_arp((struct ether_arp *)packetptr);
		return;
    	}
    	else if(ntohs(eptr->ether_type) == ETHERTYPE_IP)
	{
		ip_num++;
		iphdr = (struct ip*)packetptr;
    		if(opt[IP] == ON)
    		{
			print_ip((struct ip *)packetptr);
    		}

		strcpy(srcip, inet_ntoa(iphdr->ip_src));
    		strcpy(dstip, inet_ntoa(iphdr->ip_dst));

    		sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            		ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            		4*iphdr->ip_hl, ntohs(iphdr->ip_len));

    		// Advance to the transport layer header then parse and display
    		// the fields based on the type of hearder: tcp, udp or icmp.
    		packetptr += 4*iphdr->ip_hl;


    		switch (iphdr->ip_p)
    		{
    			case IPPROTO_TCP:
				tcp_num++;
				if(opt[TCP] == ON)
				{
					tcphdr = (struct tcphdr*)packetptr;
					print_tcp((struct tcphdr *)packetptr);
        				printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source),
               					dstip, ntohs(tcphdr->dest));
        				printf("%s\n", iphdrInfo);
        				printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               					(tcphdr->urg ? 'U' : '*'),
               					(tcphdr->ack ? 'A' : '*'),
               					(tcphdr->psh ? 'P' : '*'),
               					(tcphdr->rst ? 'R' : '*'),
               					(tcphdr->syn ? 'S' : '*'),
               					(tcphdr->fin ? 'F' : '*'),
               					ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               					ntohs(tcphdr->window), 4*tcphdr->doff);
				}
        			break;

    			case IPPROTO_UDP:
				udp_num++;
				if(opt[UDP] == ON)
				{
        				udphdr = (struct udphdr*)packetptr;
					print_udp((struct udphdr*)packetptr);
        				printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source),
               					dstip, ntohs(udphdr->dest));
        				printf("%s\n", iphdrInfo);
        			}
        			break;

    			case IPPROTO_ICMP:
				icmp_num++;
				if(opt[ICMP] == ON)
				{
					icmphdr = (struct icmphdr*)packetptr;
					print_icmp((struct icmp *)packetptr);
        				printf("ICMP %s -> %s\n", srcip, dstip);
        				printf("%s\n", iphdrInfo);
        				memcpy(&id, (u_char*)icmphdr+4, 2);
        				memcpy(&seq, (u_char*)icmphdr+6, 2);
        				printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
               					ntohs(id), ntohs(seq));
				}
				break;
    			default:
				other_num++;
				break;

    		}
	}else
	{
	 	if(opt[ALL] == ON)
	 	{
			printf("Unknown protocol\n");
			unknown_num++;
		}
	}
}





void bailout(int signo)
{
    struct pcap_stat stats;

    if (pcap_stats(pd, &stats) >= 0)
    {
	if(OFF == m)
	{
        	printf("\n%d packets received\n", /* stats.ps_recv */ ip_num + arp_num + unknown_num);
        	printf("%d packets dropped\n\n", stats.ps_drop);
	}
	printf("%d ip packets\n", ip_num);
	printf("%d arp packets\n", arp_num);
	printf("%d unknown type packets\n\n", unknown_num);

	printf("-----------IP------------\n");
	printf("%d tcp packets\n", tcp_num);
	printf("%d udp packets\n", udp_num);
	printf("%d icmp packets\n", icmp_num);
	printf("%d other ip packets\n", other_num);
	printf("%d icmp redirect packets\n", icmp_redirect);
	printf("%d icmp destination unreachable packets\n\n", icmp_unreachable);

	printf("----------Mac Address----------\n");
	for(int i = 0; i < mac_num; i++)
	{
		printf("%s\n", mac[i]);
	}
	printf("total %d mac address found\n\n", mac_num);

	getNowTime(end_time);
	printf("start time: %s",start_time);
	printf("  end time: %s\n",end_time);
    }
    pcap_close(pd);
    exit(0);
}





int main(int argc, char **argv)
{
	for(int j = 0; j<= 49; j++)
	{
		memset(mac[j], '\0', 18);
	}


	memset(start_time, 0, TIME_SIZE);
    	memset(end_time, 0, TIME_SIZE);
    	getNowTime(start_time);

    	opt[ETHER] = OFF;
    	opt[ARP]   = ON;
    	opt[IP]    = ON;
    	opt[TCP]   = ON;
    	opt[UDP]   = ON;
	opt[ICMP]  = ON;
	opt[DUMP]  = OFF;
	opt[ALL]   = OFF;

    	char interface[256] = "", bpfstr[256] = "";
    	int packets = 0, c, i;

    	// Get the command line options, if any
    	while ((c = getopt (argc, argv, "aep:dhi:n:f:")) != -1)
    	{
        	switch (c)
        	{
			case 'a':
				opt[ALL] = ON;
				break;
        		case 'h':
				printf("Usage: ./ipdump [-ahed] [-i ifname] [-p protocols] [-f filter] [-n number] \n");
            			exit(0);
            			break;
        		case 'i':
            			strcpy(interface, optarg);
            			break;
        		case 'n':
            			packets = atoi(optarg);
				m = ON;
            			break;
			case 'e':
				opt[ETHER] = ON;
				break;
			case 'd':
				opt[DUMP] = ON;
				break;
			case 'p':
				opt[ARP] = OFF;
				opt[IP] = OFF;
				opt[TCP] = OFF;
				opt[UDP] = OFF;
				opt[ICMP] = OFF;

				optind--;
				while(argv[optind] != NULL && argv[optind][0] != '-')
				{
					printf("protocol: %s\n",argv[optind]);
					if(strcmp(argv[optind], "arp") == 0)
					{
						opt[ARP] = ON;
					}
					else if(strcmp(argv[optind], "ip") == 0)
					{
						opt[IP] = ON;
					}
					else if(strcmp(argv[optind], "tcp") == 0)
					{
						opt[TCP] = ON;
					}
					else if(strcmp(argv[optind], "udp") == 0)
					{
						opt[UDP] = ON;
					}
					else if(strcmp(argv[optind],"icmp") == 0)
					{
						opt[ICMP] = ON;
					}
					else if(strcmp(argv[optind], "other") == 0)
					{
						;
					}
					else
					{
						exit(EXIT_FAILURE);
					}
					optind ++;
				}
				break;
			case 'f':
				optind--;
			while(argv[optind] != NULL && argv[optind][0] != '-')
			{
				strcat(bpfstr, argv[optind]);
        			strcat(bpfstr, " ");
				optind ++;
			}
			printf("filter expresssion:%s\n", bpfstr);
			break;
		}
	}

    	// Open libpcap, set the program termination signals then start
    	// processing packets.
    	if ((pd = open_pcap_socket(interface, bpfstr)))
    	{
        	signal(SIGINT, bailout);
        	signal(SIGTERM, bailout);
        	signal(SIGQUIT, bailout);
        	capture_loop(pd, packets, (pcap_handler)parse_packet);
        	bailout(0);
    	}
    	exit(0);
}
