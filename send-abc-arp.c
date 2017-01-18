#include <stdio.h>           // printf
#include <string.h>          // memset
#include <stdlib.h>          // for exit(0)
#include <errno.h>           // for errno
#include <unistd.h>          // for getopt()
#include <time.h>            // for nanosleep()
#include <netinet/ether.h>   // provides declarations for ethernet header
#include <netinet/if_ether.h>
// used for getting the mac address
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
// pcap lib
#include <pcap.h>

#pragma pack(1)

struct ether_abc_arp 
{
    struct arphdr ea_hdr;	/* fixed-size header */
    u_int8_t arp_sha[ETH_ALEN];	/* sender hardware address */
    uint64_t arp_spa;	        /* sender protocol address */
    u_int8_t arp_tha[ETH_ALEN];	/* target hardware address */
    uint64_t arp_tpa;           /* target protocol address */
};

// converts abc_addr into binary form (in network byte order)
uint64_t inet_abc_addr(const char* cpaddr)
{
    uint64_t l64 = 0, r64 = 0, ret = 0;
    memcpy(&l64, ether_aton(cpaddr), 6);
    memcpy(&r64, ether_aton(cpaddr + 6), 6);
    l64 &= 0x0000FFFFFFFF;
    r64 &= 0xFFFFFFFF0000;
    r64 = r64 >> 16;
    ret = (r64 << 32) + l64;
    return ret; 
}

// note that this is non-reentrant
char* get_mac_address(const char* if_name)
{
    static struct ifreq ifr;
    size_t if_name_len = strlen(if_name);
    if (if_name_len < sizeof(ifr.ifr_name)) 
    {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } 
    else 
    {
        fprintf(stderr, "interface name (%s) is too long", if_name);
        return 0;
    }

    // open an IPv4-family socket for use when calling ioctl
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) 
    {
        perror(0);
        return 0;
    }

    // obtain the source MAC address, copy into ethernet header
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) 
    {
        perror(0);
        close(fd);
        return 0;
    }
    close(fd);
    return (char*)ifr.ifr_hwaddr.sa_data;
}

void print_usage(const char* proc)
{
    fprintf(stderr, "usage: %s -i <interface> -m <dst-mac-address> -s <src-abc-address> -d <dst-abc-address> -n <pkts-num> -l <pkt-len> -r <speed 1-5> -p <ARP-opcode>\n", proc);
}
extern int opterr;

int main(int argc, char* argv[]) 
{
    char* if_name = NULL;
    char* dest_mac = NULL;
    char* source_host = NULL;
    char* dest_host = NULL;
    unsigned int pkts_num = 0;
    unsigned int pkt_len = 0;
    unsigned int speed = 0;
    unsigned short int arp_opcode = 0;
    int opt = 0;

    opterr = 0;

    // input arguments
    while((opt = getopt(argc, argv, "s:d:i:m:n:l:r:p:h")) != -1)
    {
        switch(opt)
        {
        case 'h':
            print_usage(argv[0]);
            return (1);
        case 'i':
            if_name = optarg;
            break;
        case 'm':
            dest_mac = optarg;
            break;
        case 's':
            source_host = optarg;
            break;
        case 'd':
            dest_host = optarg;
            break;
        case 'n':
            pkts_num = atoi(optarg); 
            break;
        case 'l':
            pkt_len = atoi(optarg);
            break;
        case 'r':
            speed = atoi(optarg);
            break;
        case 'p':
            arp_opcode = atoi(optarg);
            if (arp_opcode != ARPOP_REQUEST && arp_opcode != ARPOP_REPLY)
            {
                print_usage(argv[0]);
                return (1);
            }
            break;
        default:
            print_usage(argv[0]);
            return (1);
        }
    }
    
    if (if_name == NULL || dest_mac == NULL || 
        source_host[0] == 0 || dest_host[0] == 0 ||
        pkts_num == 0 || pkt_len == 0 ||
        speed == 0 || arp_opcode == 0)
    {
        print_usage(argv[0]);
        return (1);
    }

    char buffer[pkt_len];
    memset(buffer, 0x90, pkt_len);

    struct ethhdr* ether = (struct ethhdr*)buffer;
    const size_t ether_size = sizeof(struct ethhdr);
    struct ether_abc_arp* arph = (struct ether_abc_arp*)(buffer + ether_size);

    // build ethernet header
    memcpy(ether->h_source, get_mac_address(if_name), ETH_ALEN);
    struct ether_addr tmp_addr;
    ether_aton_r(dest_mac, &tmp_addr);
    memcpy(ether->h_dest, tmp_addr.ether_addr_octet, ETH_ALEN);
    ether->h_proto = htons(ETH_P_ARP);

    // fill in the ARP Header
    arph->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arph->ea_hdr.ar_pro = htons(0x6000);
    arph->ea_hdr.ar_hln = 6;
    arph->ea_hdr.ar_pln = 8;
    arph->ea_hdr.ar_op = htons(arp_opcode);
    memcpy(arph->arp_sha, ether->h_source, ETH_ALEN);
    arph->arp_spa = inet_abc_addr(source_host);
    memcpy(arph->arp_tha, ether->h_dest, ETH_ALEN);
    arph->arp_tpa = inet_abc_addr(dest_host);

    // Open a PCAP packet capture descriptor for the specified interface
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';

    pcap_t* pcap = pcap_open_live(if_name, pkt_len, 1, 1000, pcap_errbuf);

    if (pcap_errbuf[0] != '\0') 
    {
        fprintf(stderr, "failed to open pcap\n");
        fprintf(stderr, "%s\n", pcap_errbuf);
    }
    if (!pcap) 
    {
        exit(1);
    }

    struct timespec interval, rem;
    switch(speed)
    {
        case 1:
            interval.tv_sec = 1;
            interval.tv_nsec = 0 * 1000 * 1000;
            break;
        case 2:
            interval.tv_sec = 0;
            interval.tv_nsec = 100 * 1000 * 1000;
            break;
        case 3:
            interval.tv_sec = 0;
            interval.tv_nsec = 10 * 1000 * 1000;
            break;
        case 4:
            interval.tv_sec = 0;
            interval.tv_nsec = 1 * 1000 * 1000;
            break;
        case 5:
            interval.tv_sec = 0;
            interval.tv_nsec = 0 * 1000 * 1000;
            break;
        default:
            print_usage(argv[0]);
            return (1);
    }
    
    for (unsigned int i = 1; i <= pkts_num; i++)
    {
        nanosleep(&interval, &rem);
        int bytes = pcap_inject(pcap, buffer, pkt_len);
        if (bytes == -1) 
        {
            fprintf(stderr, "failed to inject packet\n");
            pcap_perror(pcap,0);
            pcap_close(pcap);
            exit(1);
        }
        else if (bytes != pkt_len)
        {
            fprintf(stderr, "only %d bytes were written to device\n", bytes);
        }
    } 
    
    // Close the PCAP descriptor
    pcap_close(pcap);
    return 0;
}
