#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const unsigned char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: live_capture eth_name\n");
        return 1;
    }
    char device[100];
    strcpy(device, argv[1]);
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* milliseconds */

    /* Open device for live capture */
    handle = pcap_open_live(
        device,
        BUFSIZ,
        packet_count_limit,
        timeout_limit,
        error_buffer);

    if (handle == NULL)
    {
        perror("pcap_open_live");
        return 1;
    }

    packet = pcap_next(handle, &packet_header);
    if (packet == NULL)
    {
        printf("No packet found.\n");
        return 2;
    }

    /* Our function to output some info */
    print_packet_info(packet, packet_header);
    return 0;
}

void print_packet_info(const unsigned char *packet, struct pcap_pkthdr packet_header)
{
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length: %d\n", packet_header.len);
}