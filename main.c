#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>

#include "Linear_lists.h"
#define ERR_ARGS 1
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


/*
 * Tato funkce slouží pro výpočet kontrolního součtu a není mým dílem.
 *
 * */
unsigned short csum(unsigned short *buf, int nwords)

{       //

    unsigned long sum;

    for(sum=0; nwords>0; nwords--)

        sum += *buf++;

    sum = (sum >> 16) + (sum &0xffff);

    sum += (sum >> 16);

    return (unsigned short)(~sum);

}
unsigned short checksum2(const char *buf, unsigned size)
{
    unsigned long long sum = 0;
    const unsigned long long *b = (unsigned long long *) buf;

    unsigned t1, t2;
    unsigned short t3, t4;

    /* Main loop - 8 bytes at a time */
    while (size >= sizeof(unsigned long long))
    {
        unsigned long long s = *b++;
        sum += s;
        if (sum < s) sum++;
        size -= 8;
    }

    /* Handle tail less than 8-bytes long */
    buf = (const char *) b;
    if (size & 4)
    {
        unsigned s = *(unsigned *)buf;
        sum += s;
        if (sum < s) sum++;
        buf += 4;
    }

    if (size & 2)
    {
        unsigned short s = *(unsigned short *) buf;
        sum += s;
        if (sum < s) sum++;
        buf += 2;
    }

    if (size)
    {
        unsigned char s = *(unsigned char *) buf;
        sum += s;
        if (sum < s) sum++;
    }

    /* Fold down to 16 bits */
    t1 = sum;
    t2 = sum >> 32;
    t1 += t2;
    if (t1 < t2) t1++;
    t3 = t1;
    t4 = t1 >> 16;
    t3 += t4;
    if (t3 < t4) t3++;

    return ~t3;
}

typedef struct {
    char* udp_range;
    char* tcp_range;
    char* interface_name;
    char* domname_or_ipaddr;
} Input_args;

int err = 0;
pcap_t *pcap_handle;
Input_args check_args(int argc, char** argv)
{
    int opt;
    Input_args input_args = { NULL, NULL, NULL,NULL};
    while (42)
    {
        static struct option long_options[] =
                {
                        /* These options don’t set a flag.
                          We distinguish them by their indices. */
                        {"i",     required_argument, 0, 'i'},
                        {"pt",  required_argument,    0, 't'},
                        {"pu",  required_argument, 0, 'u'}
                };

        int option_index = 0;

        opt = getopt_long_only (argc, argv, "i:u:t:", long_options, &option_index);
        if(opt == -1)
            break;

        switch(opt)
        {
            case 'i':
                // printf("%c: %s\n", opt, optarg);
                input_args.interface_name = optarg;
                break;
            case 't':
                //printf("%c: %s\n", opt, optarg);
                input_args.tcp_range = optarg;
                break;
            case 'u':
                input_args.udp_range = optarg;
                //printf("%c: %s\n", opt, optarg);
                break;
            default:
                fprintf(stderr, "Error: Unknown input argument. Please check your input.\n");
        }

    }
    if(optind < argc) {
        input_args.domname_or_ipaddr = argv[optind]; //next arguments ignored
    }

    if(!(input_args.tcp_range && input_args.udp_range && input_args.domname_or_ipaddr))
    {
        fprintf(stderr, "Error: Please specify udp range, tcp range and domain name or IP address.\n");
        err = ERR_ARGS;
    }
    return input_args;
}

Linlist_string *get_string_range(char *str) {
    Linlist_string* temp_list = malloc(sizeof(Linlist_string));
    char *splitted = strtok(str, ",");
    if(strstr(splitted, "-"))
    {
        char *start_str = strtok(splitted, "-");
        char *stop_str = strtok(NULL, "-");
        int start = strtoul(start_str, NULL, 10);
        int stop = strtoul(stop_str, NULL, 10);
        if(start > stop)
        {
            fprintf(stderr, "Error: Please specify udp range, tcp range and domain name or IP address.\n");
            err = ERR_ARGS;
        }

        for(int n = start; n < stop+1; n++)
        {
            char temp_string[5];
            memset (temp_string, 0, 5);
            sprintf(temp_string, "%d", n);
            string_write(temp_string,temp_list);
        }
        free(temp_list);
        return temp_list;
    }
    while(splitted != NULL)
    {
        string_write(splitted, temp_list);
        splitted = strtok(NULL, ",");
    }

    return temp_list;
}
Linlist_int *get_range(Linlist_string *list) {
    Linlist_int* range = malloc(sizeof(Linlist_int));
    if(list == NULL || list->first == NULL)
        return NULL;
    struct string_elem *temp = list->first;
    while(temp != NULL)
    {
        int temp_int = strtol(temp->data,NULL, 10);
        int_write(&temp_int, range);
        temp = temp->next;
    }
    return range;
}
void alarm_handler(int sig) {
    pcap_breakloop(pcap_handle);
}
char* get_dst_addr(char *domain_name)
{
    struct addrinfo* result;
    getaddrinfo(domain_name, NULL, NULL, &result);
    struct addrinfo *addr = result;
    char *temp_addr =  malloc(sizeof(char)*39);
    if(temp_addr == NULL)
    {
        return NULL;
    }
    while(addr != NULL)
    {
        if(!addr->ai_addr)
        {
            addr = addr->ai_next;
            continue;
        }
        struct sockaddr_in* temp = (struct sockaddr_in*)(addr->ai_addr);

        inet_ntop(temp->sin_family,&(temp->sin_addr), temp_addr,39);
        return temp_addr;
        printf("Adresa cile: %s\n", temp_addr);
        addr = addr->ai_next;
    }
}

char* get_src_addr(char *interface_name, char *netmask)
{
    struct ifaddrs *interface_names = NULL;
    if(getifaddrs(&interface_names))
    {
        exit(43);
    }
    struct ifaddrs *head = interface_names;
    struct ifaddrs *backup = interface_names;


    int found = 0;
    struct sockaddr_in *temp_sockaddr;
    struct sockaddr_in *temp_mask;
    while(head != NULL)
    {

        //printf("Hledani interface %s, %s: %d, ifa_addr: ", interface_name, head->ifa_name, strcmp(interface_name, head->ifa_name));
        /*for (int i = 0; i < sizeof(head->ifa_addr->sa_data); ++i) {
            printf("%hhu ", head->ifa_addr->sa_data[i]);
        }printf("\n");*/


        if(strcmp(interface_name, head->ifa_name) == 0)
        {
            if(head->ifa_addr->sa_family == AF_INET || head->ifa_addr->sa_family == AF_INET6 )
            {
                found = 1;
                temp_sockaddr = (struct sockaddr_in*)head->ifa_addr;
                temp_mask = (struct sockaddr_in*)head->ifa_netmask;
                break;
            }
        }
        head = head->ifa_next;
    }
    if(!found )
    {
        exit(88);
    }
    char* src_addr = malloc(sizeof(char)*39);
    inet_ntop(AF_INET,&(temp_sockaddr->sin_addr), src_addr,39);
    inet_ntop(AF_INET,&(temp_mask->sin_addr), netmask,39);
    freeifaddrs(backup);
    return src_addr;
}

void set_tcp_header(struct tcphdr *tcp_header, int port, struct sockaddr_in sendto_src) {
    tcp_header->source = sendto_src.sin_port;
    tcp_header->dest = htons(port); //TODO TOHLE BUDU MENIT V CYKLU
    tcp_header->seq = htonl(1); //WTF
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;	//tcp header size
//nastaveni "flagu"
    tcp_header->fin=0;
    tcp_header->syn=1;
    tcp_header->rst=0;
    tcp_header->psh=0;
    tcp_header->ack=0;
    tcp_header->urg=0;
    tcp_header->res1 = 0;
    tcp_header->res2 = 0;
    tcp_header->urg_ptr = 0;
    tcp_header->window = htons(64240);	/* maximum allowed window size */
    tcp_header->check = 0;	//leave checksum 0 now, filled later by pseudo header
    tcp_header->th_urp = 0;

}

void set_ip_header(struct ip *ip_header, char *src_addr, char *dst_addr, int size, int tcp)
{
    //ip header here
    ip_header->ip_v = 4;
    ip_header->ip_hl = sizeof*ip_header >> 2;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(size);//celkova velikost paketu
    ip_header->ip_id = htons(36458);
    ip_header->ip_off = htons(0);
    ip_header->ip_ttl = 255;
    if(tcp)
        ip_header->ip_p = IPPROTO_TCP;
    else
        ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = 0;

    ip_header->ip_src.s_addr = inet_addr(src_addr);
    ip_header->ip_dst.s_addr = inet_addr(dst_addr);

    ip_header->ip_sum = csum((unsigned short *)ip_header, size); //druhá možnost: velikost iphlavy + protokolhlavy

}
//http://minirighi.sourceforge.net/html/udp_8c-source.html
uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
 {
         const uint16_t *buf=buff;
         uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
         uint32_t sum;
         size_t length=len;

         // Calculate the sum                                            //
         sum = 0;
         while (len > 1)
         {
                 sum += *buf++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                 len -= 2;
         }

         if ( len & 1 )
                 // Add the padding if the packet lenght is odd          //
                 sum += *((uint8_t *)buf);

         // Add the pseudo-header                                        //
         sum += *(ip_src++);
         sum += *ip_src;

         sum += *(ip_dst++);
         sum += *ip_dst;

         sum += htons(IPPROTO_UDP);
         sum += htons(length);

         // Add the carries                                              //
         while (sum >> 16)
                 sum = (sum & 0xFFFF) + (sum >> 16);

       // Return the one's complement of sum                           //
         return ( (uint16_t)(~sum)  );
 }

int main(int argc, char** argv )
{

    Input_args input_args = check_args(argc,argv);
    if(err)
    {
       exit(ERR_ARGS);
    }
    Linlist_string *string_TCP_range = get_string_range(input_args.tcp_range);
    Linlist_string *string_UDP_range = get_string_range(input_args.udp_range);
    Linlist_int *TCP_range = get_range(string_TCP_range);
    Linlist_int *UDP_range = get_range(string_UDP_range);

    /*int *el = int_read(TCP_range);
    char *els = string_read(string_TCP_range);
    while(el != NULL && els != NULL)
    {
        printf("%d %s\n", *el, els);
        el = int_read(TCP_range);
        els = string_read(string_TCP_range);
    }
    exit(11);*/

    char * dst_addr = get_dst_addr(input_args.domname_or_ipaddr);
    char *interface_name = input_args.interface_name ? input_args.interface_name : "eth0";
    char *mask = malloc(sizeof(char)*39);
    char* src_addr = get_src_addr(interface_name, mask);
    printf("dst: %s, src: %s, mask: %s\n", dst_addr, src_addr, mask);

    //start TCP scanning
    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock <0)
    {
        exit(43);
    }
    int one = 1;
    err = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if(err)
    {
        exit(43);
    }

    //starts to scan TCP sockets
    int * port = int_read(TCP_range);
    char *str_port = string_read(string_TCP_range);

    while(port != NULL && str_port != NULL) //main cycle, here, all ports are scanned. New pacekt created every time.
    {
        int size = (sizeof(struct ip) + sizeof(struct tcphdr)) * sizeof(char);
        char packet[size];
        memset (packet, 0, size);
        struct ip* ip_header = (struct ip*)packet;
        struct tcphdr *tcp_header = (struct tcphdr *) (packet + sizeof (struct ip));
        struct sockaddr_in sendto_src;
        struct pseudo_header pseudo;

        //structure to identify source == myself
        sendto_src.sin_addr.s_addr = inet_addr(dst_addr); //src address
        sendto_src.sin_family = AF_INET;
        sendto_src.sin_port = htons(46666); //port from which i send packets


        set_ip_header(ip_header, src_addr, dst_addr, size,1);
        set_tcp_header(tcp_header, *port, sendto_src);


        //pseudoheader for checksum
        pseudo.source_address = inet_addr(src_addr);
        pseudo.dest_address = inet_addr(dst_addr);
        pseudo.placeholder = 0;
        pseudo.protocol = IPPROTO_TCP;
        pseudo.tcp_length = htons(sizeof(struct tcphdr));
        //checksum itself. Relatively difficult part, no function for this time
        int pseudo_size = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(pseudo_size);
        memcpy(pseudogram , (char*) &pseudo , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcp_header , sizeof(struct tcphdr));
        tcp_header->check = checksum2((const char*) pseudogram , pseudo_size);

        //prepare PCAP
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_handle = pcap_open_live(interface_name, 65500, 0, 100, errbuf);
        if(pcap_handle == NULL)
        {
            printf("ERR during creating pcap_handle");
            exit(43);
        }
        bpf_u_int32 pcap_mask;
        bpf_u_int32 pcap_net;
        pcap_lookupnet(interface_name, &pcap_net, &pcap_mask, errbuf);

        //setting the rule: src port has to be the same
        char rule[9+5+1]= "src port ";
        strcat(rule, str_port);
        struct bpf_program *filter=(struct bpf_program *)malloc(sizeof(struct bpf_program));;
        pcap_compile(pcap_handle ,filter, rule, 0, pcap_net);
        if(err)
        {
            printf("err during pcap compile. %d", err);
            exit(43);
        }
        err = pcap_setfilter(pcap_handle,filter);
        if(err == -1)
        {
            printf("err during pcap set filter.");
            exit(43);
        }
        struct pcap_pkthdr *header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr ));
        const  u_char *arrived_packet;

        if(sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&sendto_src, sizeof(sendto_src)) < 0)
        {
            perror("sendto err\n");
        }
        while(42)
        {
            alarm(1);
            signal(SIGALRM, alarm_handler);
            arrived_packet = pcap_next(pcap_handle, header);
            if(arrived_packet)
            {
                printf("Packet arrived! %d\n", header->len);
                //struct sniff_ethernet*eth_h = (struct sniff_ethernet*)(arrived_packet);
                struct ip*sniffed_ip = (struct ip*)(arrived_packet+ 14); //14 == sizeof(sniff_eth)
                struct tcphdr* sniffed_tcp = (struct tcphdr*)(arrived_packet+14+ sizeof(struct ip));
                char * s_ip = malloc(sizeof(char)*39);
                inet_ntop(AF_INET, &(sniffed_ip->ip_src), s_ip, 39);
                printf("sniffed IP: %s, tcp ack: %u, bla :) %u %u\n",s_ip, sniffed_tcp->ack, sniffed_tcp->source, tcp_header->dest);
                if(sniffed_tcp->source == tcp_header->dest)
                {
                    if(sniffed_tcp->ack && !sniffed_tcp->rst)
                    {
                        printf("%d tcp: open\n", *port);
                        break;
                    }
                    else
                    {
                        printf("%d tcp: closed\n", *port);
                        break;
                    }
                }
            }
            else
            {
                printf("%d tcp: filtered\n", *port);
                break;
            }
        }//end of while42
            pcap_close(pcap_handle);

        //set new ports for next cycle
         port = int_read(TCP_range);
         str_port = string_read(string_TCP_range);
    }
    close(sock); //end of TCP scanning

    int udp_size = (sizeof(struct ip) + sizeof(struct udphdr)) * sizeof(char);
    char datagram[udp_size];
    memset (datagram, 0, udp_size);
    struct ip* ip_header = (struct ip*)datagram;
    struct udphdr*udp = (struct udphdr *) (datagram + sizeof(struct ip));
    set_ip_header(ip_header, src_addr, dst_addr, udp_size, 0);


    //there are two implementations of udphdr:
    // source/uh_sport
    // dest/uh_dport
    // len/uh_len
    //check/uh_sum
    udp->source= htons(46666);
    udp->dest = htons(1000); //TODO tohle menit
    //printf("delka: %d", sizeof(struct udphdr));
    udp->len = htons(sizeof(struct udphdr));
    udp->check = udp_checksum(udp, sizeof(struct udphdr), inet_addr(src_addr), inet_addr(dst_addr));




    sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sock < 0)
    {
        exit(43);
    }
    int recvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(recvsock < 0)
    {
        exit(43);
    }

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        exit(-1);
    }
    else

        printf("setsockopt() is OK.\n");

    struct sockaddr_in sendto_src;
    //structure to identify source == myself
    sendto_src.sin_addr.s_addr = inet_addr(dst_addr); //src address
    sendto_src.sin_family = AF_INET;
    sendto_src.sin_port = htons(46666); //port from which i send packets

    //prepare PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(interface_name, 65500, 0, 100, errbuf);
    if(pcap_handle == NULL)
    {
        printf("ERR during creating pcap_handle");
        exit(43);
    }
    bpf_u_int32 pcap_mask;
    bpf_u_int32 pcap_net;
    pcap_lookupnet(interface_name, &pcap_net, &pcap_mask, errbuf);

    //setting the rule: src port has to be the same
    char rule[9+5+1]= "ip proto \\icmp";
    //strcat(rule, str_port);
    struct bpf_program *filter=(struct bpf_program *)malloc(sizeof(struct bpf_program));;
    pcap_compile(pcap_handle ,filter, rule, 0, pcap_net);
    if(err)
    {
        printf("err during pcap compile. %d", err);
        exit(43);
    }
    err = pcap_setfilter(pcap_handle,filter);
    if(err == -1)
    {
        printf("err during pcap set filter.");
        exit(43);
    }
    struct pcap_pkthdr *header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr ));
    const  u_char *arrived_packet;
    if(sendto(sock, datagram, sizeof(datagram), 0, (struct sockaddr *)&sendto_src, sizeof(sendto_src)) < 0)
    {
        perror("sendto err\n");
    }

    int second = 0;
    while(42)
    {
        alarm(1);
        signal(SIGALRM, alarm_handler);
        arrived_packet = pcap_next(pcap_handle, header);
        if(arrived_packet)
        {
            printf("ICMP Packet arrived! %d\n", header->len);
            break;
        }
        else
        {
            if(second)
            {
                //druhe odeslani bez nalezeni paketu, open/filtered
                printf("open or filtered?\n");
                break;
            }
            else
            {
                printf("gimme second chance!\n");
                second = 1;
                if(sendto(sock, datagram, sizeof(datagram), 0, (struct sockaddr *)&sendto_src, sizeof(sendto_src)) < 0)
                {
                    perror("sendto err\n");
                }
            }


        }

    }
    pcap_close(pcap_handle);
//todo sendto_src prejmenovat na sendto dst
    exit(42);
}
