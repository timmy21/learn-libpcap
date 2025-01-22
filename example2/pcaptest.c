#include "pcaptest.h"
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>

// ip地址转换示例
void TestIpv6()
{
    char ipv6_addr[64];
    // 内嵌 IPv4 地址的 IPv6 地址
    // 该函数将字符串 src 转换为 af 地址簇中的网络地址结构，然后将网络地址结构复制到 dst。af参数必须是 AF_INET 或 AF_INET6.
    // inet_pton() 成功时返回 1（网络地址已成功转换）。如果 src 不包含表示指定地址族中有效网络地址的字符串，则返回0.
    // 如果 af 不包含有效的地址族，则返回 -1 并将 errno 设置为 EAFNOSUPPORT。
    // inet_pton(AF_INET6, "0:0:0:0:0:0:192.168.200.65", ipv6_addr);
    inet_pton(AF_INET6, "::ffff:192.168.200.65", ipv6_addr);
    printf("%s\n", ipv6_addr);

    char ipv6_str[64] = {'\0'};
    // 该函数将 af 地址族中的网络地址结构 src 转换为字符串。结果字符串被复制到 dst 指定的缓冲区，该缓冲区必须是一个非 NULL 指针。调用者在参数大小中指定此缓冲区中可用的字节数
    // 成功时，inet_ntop() 返回一个指向 dst 的非 NULL 指针。如果发生错误，则返回 NULL，并设置 errno 以指示错误。
    inet_ntop(AF_INET6, ipv6_addr, ipv6_str, 64);
    printf("%s\n", ipv6_str);
}

void TestIpv4()
{
    int ipv4_addr;
    inet_pton(AF_INET, "192.168.200.65", &ipv4_addr);
    printf("%d\n", ipv4_addr);

    char ipv4_str[64] = {'\0'};
    inet_ntop(AF_INET, &ipv4_addr, ipv4_str, 64);

    printf("%s\n", ipv4_str);
}

/***************内部调用******************/
// 解析链路层 IP TCP
void printPKInfo(const struct pcap_pkthdr *header, const __u_char *packet)
{
    printf("数据包捕获时间: %s", ctime(&header->ts.tv_sec));
    printf("数据包捕获长度: %d\n", header->caplen);
    printf("数据包长度: %d\n", header->len);

    for (int i = 0; i < header->caplen; ++i)
    {
        if (i % 8 == 0 && i > 7)
            printf("\n");
        printf("%x\t", packet[i]);
    }
    printf("\n");

    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    /* Pointers to start point of various headers */
    const __u_char *ip_header;
    const __u_char *tcp_header;
    const __u_char *payload;

    /* Find start of IP header */
    ip_header = packet + ETHER_HDR_LEN;

    // ip层前8个位为4位版本 + 4位长度
    int ip_header_length = ((*ip_header) & 0x0F);
    // 首部长度的记录都是按照4个字节的单位进行增减的，所以我们算出4bit的部首长度的值之后，乘以4个字节，就可以知道首部的长度了，一个字节代表了8bit
    ip_header_length = ip_header_length * 4;
    printf("IP头长度: %d\n", ip_header_length);

    // 获取协议层
    __u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP)
    {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    // 获取ip地址
    int src, dest;
    memcpy(&src, ip_header + 12, 4);
    memcpy(&dest, ip_header + 16, 4);

    char ipv4_src[64] = {'\0'};
    inet_ntop(AF_INET, &src, ipv4_src, 64);
    printf("源IP: %s\n", ipv4_src);

    char ipv4_dest[64] = {'\0'};
    inet_ntop(AF_INET, &dest, ipv4_dest, 64);
    printf("目标IP: %s\n", ipv4_dest);

    // tcp头开始位置
    tcp_header = packet + ETHER_HDR_LEN + ip_header_length;

    uint16_t srcport1, srcport2, destport1, destport2;
    memcpy(&srcport1, tcp_header, 2);
    memcpy(&destport1, tcp_header + 2, 2);

    srcport2 = ntohs(srcport1);
    destport2 = ntohs(destport2);

    printf("srcPort: %d\n", srcport2);
    printf("destPort: %d\n", destport2);

    // tcp长度: tcp首部偏移12字节后前4位为长度
    int tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    printf("TCP 头长度: %d\n", tcp_header_length);

    // 协议头总长度
    int total_headers_size = ETHER_HDR_LEN + ip_header_length + tcp_header_length;
    printf("所有协议头总长度: %d bytes\n", total_headers_size);

    // 数据长度
    int payload_length = header->caplen - total_headers_size;
    printf("有效数据长度: %d bytes\n", payload_length);

    // 数据头
    payload = packet + total_headers_size;
    printf("有效数据内存地址: %p\n", payload);
    printf("有效数据:[\n");
    if (payload_length > 0)
    {
        const __u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length)
        {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
    }
    printf("]\n\n");
}

// 回调函数 loop 回调用
void my_loop(__u_char *args,
             const struct pcap_pkthdr *header,
             const __u_char *packet)
{
    printPKInfo(header, packet);
    return;
}

// 回调函数 保存文件回调
void processPacket(__u_char *args,
                   const struct pcap_pkthdr *header,
                   const __u_char *packet)

{
    /*
    void pcap_dump(u_char *user, struct pcap_pkthdr *h,u_char *sp)
    向调用pcap_dump_open()函数打开的文件输出一个数据包。该函数可作为pcap_dispatch()函数的回调函数。
    */
    pcap_dump(args, header, packet);
    printf("Received Packet Size: %d\n", header->len);
    return;
}

/*******************************************外部调用**************************************************/
void testCapLoop()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device = pcap_lookupdev(error_buffer); // 获取第一个可以捕获的设备
    if (device == NULL)
    {
        printf("错误 未找到设备: %s\n", error_buffer);
        return;
    }

    /* 打开网络接口 */
    pcap_t *handle = pcap_open_live(
        device, // 设备名称
        BUFSIZ, // snaplen
        1,      // 混合模式
        10000,  // 超时时间
        error_buffer);

    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return;
    }

    printf("start capture device: %s\n", device);

    /*
     int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
     p:需要捕获的设备
     cnt:捕获的包个数 0 代表一直捕获
     callback：回调函数 原型如下
     user: 回调函数的参数

     typedef void (*pcap_handler)(u_char *args, const struct pcap_pkthdr *header,
                  const u_char *packet);
      args: 回调函数传递的参数 user
      header: 捕获包信息
      packet: 数据包
     */
    pcap_loop(handle, 0, my_loop, NULL);
    pcap_close(handle);
    return;
}

void testCapAndSaveFile()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device = pcap_lookupdev(error_buffer);
    if (device == NULL)
    {
        printf("错误 未找到设备: %s\n", error_buffer);
        return;
    }

    /* 打开网络接口 */
    pcap_t *handle = pcap_open_live(
        device,
        BUFSIZ,
        1,
        10000,
        error_buffer);

    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return;
    }

    /* 打开需要写入的文件 */
    pcap_dumper_t *out_pcap = pcap_dump_open(handle, "test.pcap");

    /* 捕获数据包并且写入文件 */
    pcap_loop(handle, 20, processPacket, (__u_char *)out_pcap);

    /* 刷新 */
    pcap_dump_flush(out_pcap);
    // 关闭文件
    pcap_dump_close(out_pcap);
    pcap_close(handle);
}

void testOpenCapFile()
{
    char *filename = "test.pcap";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open file %s: %s\n", filename, error_buffer);
        return;
    }
    pcap_loop(handle, 0, my_loop, NULL);
}