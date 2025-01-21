#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <iomanip>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // 存储错误信息
    pcap_if_t *alldevs;            // 链表头指针，用于存储所有设备
    pcap_if_t *device;             // 遍历链表的指针

    // 获取所有设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    // 遍历设备链表并打印信息
    std::cout << "Available Devices:" << std::endl;
    int i = 0;
    for (device = alldevs; device != nullptr; device = device->next)
    {
        std::cout << ++i << ". Device Name: " << device->name << std::endl;
        for (pcap_addr *addr = device->addresses; addr != nullptr; addr = addr->next)
        {
            if (addr->addr == nullptr)
            {
                std::cerr << "    Address is null." << std::endl;
                continue;
            }

            switch (addr->addr->sa_family)
            {
            case AF_INET:
            {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)(addr->addr);
                if (inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof(ip)) == NULL)
                {
                    std::cerr << "inet_ntop" << std::endl;
                }
                else
                {
                    std::cout << "    IPv4 Address: " << ip << std::endl;
                }
                break;
            }
            case AF_INET6:
            {
                char ip[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)(addr->addr);
                if (inet_ntop(AF_INET, &ipv6->sin6_addr, ip, sizeof(ip)) == NULL)
                {
                    std::cerr << "inet_ntop" << std::endl;
                }
                else
                {
                    std::cout << "    IPv6 Address: " << ip << std::endl;
                }
                break;
            }
            case AF_PACKET:
            {
                struct sockaddr_ll *sll = (struct sockaddr_ll *)(addr->addr);
                std::cout << "    Link Layer Address (MAC): ";
                for (int i = 0; i < sll->sll_halen; ++i)
                {
                    if (i > 0)
                        std::cout << ":";
                    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)(unsigned char)sll->sll_addr[i];
                }
                std::cout << std::dec << std::endl;
                break;
            }
            default:
            {
                std::cout << "    Unknown Address Family: " << addr->addr->sa_family << std::endl;
                break;
            }
            }
        }

        if (device->description)
        {
            std::cout << "    Description: " << device->description << std::endl;
        }
        else
        {
            std::cout << "    Description: (No description available)" << std::endl;
        }
    }

    // 释放设备列表
    pcap_freealldevs(alldevs);
    return 0;
}