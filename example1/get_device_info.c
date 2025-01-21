#include <stdio.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>

// 函数声明
char *get_device_ip(const char *device_name);

int main(int argc, char **argv)
{
    char *device;
    char ip_net[INET_ADDRSTRLEN];
    char subnet_mask[INET_ADDRSTRLEN];

    bpf_u_int32 ip_net_raw;      /* IP address as interger */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as interger */
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    struct in_addr address;              /* Used for both ip_net & subnet */

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL)
    {
        printf("%s\n", error_buffer);
        return 1;
    }

    /* Get device info */
    // pcap_lookupnet 返回的是设备所在的网络号(ip_net_raw)
    lookup_return_code = pcap_lookupnet(
        device,
        &ip_net_raw,
        &subnet_mask_raw,
        error_buffer);

    if (lookup_return_code == -1)
    {
        printf("%s\n", error_buffer);
        return 1;
    }

    /*
    If you call inet_ntoa() more than once
    you will overwrite the buffer. If we only stored
    the pointer to the string returned by inet_ntoa(),
    and then we call it again later for the subnet mask,
    out first pointer (ip_net address) will actually have
    the contents of the subnet mask. That is why we are
    using a string copy to grab the contents while it is fresh.
    The pointer returned by inet_ntoa() is always the same.

    This is from the man:
    The inet_ntoa() function converts the Internet host address in,
    given in network byte order, to a string in IPv4 dotted-decimal
    notation. The string is returned in a statically allocated
    buffer, which subsequent calls will overwrite.
    */

    /* Get ip_net in human readable form */
    address.s_addr = ip_net_raw;
    strcpy(ip_net, inet_ntoa(address));
    if (ip_net == NULL)
    {
        perror("inet_ntoa"); /* print error*/
        return 1;
    }

    /* Get subnet mask in human readable from */
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL)
    {
        perror("inet_ntoa");
        return 1;
    }

    char *ip = get_device_ip(device);
    if (ip == NULL)
    {
        perror("get_device_ip");
        return 1;
    }

    printf("Device: %s\n", device);
    printf("IP network address: %s\n", ip_net);
    printf("IP address: %s\n", ip);
    printf("Subnet mask: %s\n", subnet_mask);

    return 0;
}

char *get_device_ip(const char *device_name)
{
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN];
    char *result = NULL;

    // 获取网络接口列表
    if (getifaddrs(&ifaddr) == -1)
    {
        /*
        当系统调用或库函数返回错误时，它们通常会设置一个全局变量 errno，以表明错误类型。
        perror会根据当前errno的值打印对应的错误消息。
        替代方案：fprintf(stderr, "getifaddrs error: %s\n", strerror(errno));
        */
        perror("getifaddrs");
        return NULL;
    }

    // 遍历网络接口
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
        {
            continue;
        }

        // 检查是否是 IPv4 地址，并且匹配设备名称
        if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, device_name) == 0)
        {
            /*
            ifa_addr 的类型为 struct sockaddr*，它是一个通用指针，支持多种协议簇 (IPv4, IPv6)
            对于 IPv4 地址，struct sockaddr_in 提供了更具体的字段，例如：sin_addr，所以需要进行类型转换
            */
            struct sockaddr_in *addr = (struct sockaddr_in *)(ifa->ifa_addr);

            // 转换为点分十进制格式
            if (inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN) == NULL)
            {
                perror("inet_ntop");
                continue;
            }

            // 动态分配内存保持 IP 地址
            result = strdup(ip); // 分配内存并复制 IP 字符串
            break;
        }
    }

    // 释放内存
    freeifaddrs(ifaddr);
    return result;
}