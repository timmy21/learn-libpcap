#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
    const char *version = pcap_lib_version();
    if (version == NULL)
    {
        perror("pcap_lib_version");
        return 2;
    }
    printf("%s\n", version);
    return 0;
}