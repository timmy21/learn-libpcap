## 网络编程
* libpcap函数：https://www.tcpdump.org/manpages/libpcap-1.10.2/
* 网络编程中常用的头文件
    * arpa/inet.h: 位于POSIX标准库中，用于网络编程。它包含了一些函数原型和定义，用于处理 IP 地址的转换和操作。
    * sys/socket.h: 通常用于 UNIX/Linux 系统中进行套接字编程。它包含了一些常量、数据结构和函数原型，用于创建和操作套接字（sockets）。
        * 定义了套接字类型的常量，例如 SOCK_STREAM、SOCK_DGRAM 等。
        * 声明了套接字操作相关的函数原型，例如 socket()、bind()、listen()、accept()、connect()、send()、recv() 等。
    * netinet/in.h:
        * struct sockaddr_in: 用于表示 IPv4 地址结构。
        * struct sockaddr_in6: 用于表示 IPv6 地址结构。
        * INADDR_ANY: 表示任意 IPv4 地址。
        * IN6ADDR_ANY_INIT: 表示任意 IPv6 地址。
        * IPPROTO_TCP、IPPROTO_UDP 等:表示 TCP 和 UDP 协议。
        * 网络字节序和主机字节序转换函数: htonl()、htons()、ntohl()、ntohs()
* TCP,IP,Ether结构体
    * linux/if_ether.h
    * netinet/ip.h
    * netinet/tcp.h


## pcap filter
1. https://ivanzz1001.github.io/records/post/linux/2017/10/24/linux-pcap-filter
1. https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFilterSection.html
1. https://www.tcpdump.org/manpages/pcap-filter.7.html
1. https://wiki.wireshark.org/CaptureFilters


### 参考资料
1. https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/contents.html
1. socket编程中需要用到的头文件: https://www.cnblogs.com/pengyingh/articles/2355732.html
1. 网络编程中常用的头文件: https://zhuanlan.zhihu.com/p/684200690
1. https://qbsuranalang.gitbooks.io/network-packet-programming/content/
1. https://www.devdungeon.com/content/using-libpcap-c
1. https://www.opensourceforu.com/2011/02/capturing-packets-c-program-libpcap/
1. pcap文件格式: https://www.cnblogs.com/studywithallofyou/p/17137325.html
1. pcapng文件格式: https://pcapng.com/
