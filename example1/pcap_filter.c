#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

void my_packet_handler(
    __u_char *args,
    const struct pcap_pkthdr *packet_header,
    const __u_char *packet_body);

void print_packet_info(const unsigned char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: load_pcap_file file_name filter_exp\n");
        return 1;
    }
    char device[100];
    strcpy(device, argv[1]);
    char filter_exp[100];
    strcpy(filter_exp, argv[2]);
    printf("device: %s\n", device);
    printf("filter_expr: %s\n", filter_exp);

    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;

    if (pcap_lookupnet(device, &ip, &subnet_mask, error_buffer) == -1)
    {
        printf("Could not get information for device: %s\n", device);
        ip = 0;
        subnet_mask = 0;
    }

    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open %s: %s\n", device, error_buffer);
        return 2;
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == PCAP_ERROR)
    {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &filter) == PCAP_ERROR)
    {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, 0, my_packet_handler, NULL);
    return 0;
}

void my_packet_handler(
    __u_char *args,
    const struct pcap_pkthdr *packet_header,
    const __u_char *packet)
{
    print_packet_info(packet, *packet_header);

    /* The packet is larger than the ether_header struct,
       but we just want to look at the first part of the packet
       that contains the header. we force the compiler
       to treat the pointer to the packet as just a pointer
       to the ether_header. The data payload of the packet comes
       after the headers. Different packet types have different header
       lengths though, but the ethernet header is always the same (14 bytes) */
    struct ether_header *eth_header;

    eth_header = (struct ether_header *)packet;

    uint16_t ether_type = ntohs(eth_header->ether_type);
    if (ether_type == ETHERTYPE_IP)
    {
        printf("IP\n");
    }
    else if (ether_type == ETHERTYPE_ARP)
    {
        printf("ARP\n");
    }
    else if (ether_type == ETHERTYPE_REVARP)
    {
        printf("Reverse ARP\n");
    }
    else
    {
        printf("ether_type: %d\n", ether_type);
    }

    return;
}

void print_packet_info(const unsigned char *packet, struct pcap_pkthdr packet_header)
{
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length: %d\n", packet_header.len);
}