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
    if (argc != 2)
    {
        printf("Usage: load_pcap_file file_name\n");
        return 1;
    }
    char file_name[100];
    strcpy(file_name, argv[1]);

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(file_name, error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not load file %s: %s\n", file_name, error_buffer);
        return 2;
    }

    pcap_loop(handle, 0, my_packet_handler, NULL);
    pcap_close(handle);
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