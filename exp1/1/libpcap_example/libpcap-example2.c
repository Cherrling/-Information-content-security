#include<stdio.h>
#include<pcap.h>
#include<time.h>

#include<unistd.h>


#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

 void  callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
 {

                     int * id = (int *)user;

                    struct in_addr addr;
                struct iphdr *ipptr;
                struct tcphdr *tcpptr;//太次片，，ip，tcp数据结构
                struct ether_header *eptr;//以太网字头
                u_char *ptr;
                char *data;
                int i;
              printf("id: %d\n", ++(*id));
                  printf("Packet length: %d\n", pkthdr->len);
                  printf("Number of bytes: %d\n", pkthdr->caplen);
                  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));



          eptr = (struct ether_header*)packet;//得到以太网字头
                if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
                {
                    printf ("Ethernet type hex:%x dec:%d is an IP packet/n",
                                ntohs(eptr->ether_type), ntohs(eptr->ether_type));
                }
                else
                {
                    if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
                    {
                        printf ("Ethernet type hex:%x dec:%d is an ARP packet/n",
                                    ntohs(eptr->ether_type), ntohs(eptr->ether_type));
                    }
                    else
                    {
                        printf ("Ethernet type %x not IP/n", ntohs(eptr->ether_type));
                        exit (1);
                    }
                }

    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf ("i=%d/n", i);
    printf ("Destination Address: ");
    do
    {
        printf ("%s%x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
    }while(--i>0);
    printf ("/n");
    //printf ("%x/n",ptr);

    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf ("Source Address: ");
    do
    {
        printf ("%s%x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
    }while(--i>0);
    printf ("/n");
    printf ("Now decoding the IP packet.\n");
    ipptr = (struct iphdr*)(packet+sizeof(struct ether_header));//得到ip包头

    printf ("the IP packets total_length is :%d\n", ipptr->tot_len);
    printf ("the IP protocol is %d\n", ipptr->protocol);
     printf("\n\n");
    addr.s_addr = ipptr->daddr;
    printf ("Destination IP: %s\n", inet_ntoa(addr));
    addr.s_addr = ipptr->saddr;
    printf ("Source IP: %s\n", inet_ntoa(addr));

    printf ("Now decoding the TCP packet.\n");
    tcpptr = (struct iphdr*)(packet+sizeof(struct ether_header)
                                    +sizeof(struct iphdr));//得到tcp包头
    printf ("Destination port : %d\n", tcpptr->dest);
    printf ("Source port : %d\n", tcpptr->source);
    printf ("the seq of packet is %d\n", tcpptr->seq);
//以上关于ip、tcp的结构信息请查询/usr/include/linux/ip.h | tcp.h

    data = (char*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr)
                                    +sizeof(struct tcphdr));//得到数据包里内容，不过一般为乱码。
     printf("\n\n");
    printf ("the content of packets is /n%s/n",data);



 }
int main()
{
    char *device;
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *head;

    device = pcap_lookupdev(errBuf);
    if(device)
        {
            printf("lookup is ok %s\n",device);
        }
        else
        {
            printf("lookup is error %s\n",errBuf);
            return 0;
        }
        head = pcap_open_live(device,65535,1,0,errBuf);
        if(head)
            {
                printf("open is ok\n");
            }
            else
            {
                    printf("open is error %s\n",errBuf);
                    return 0;
            }

            // typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

      // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
      int i = 0;
       pcap_dispatch(head, 0,callback, (u_char *)&i);

       pcap_close(head);
       return 0;
}
