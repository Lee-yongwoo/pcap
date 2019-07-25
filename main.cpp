#include <arpa/inet.h>
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define ETH_LEN 14
#define MAC_LEN 6
#define IP_LEN 4


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void print_ip(in_addr ip) {
    printf("%s\n",inet_ntoa(ip));
}

void print_port(uint16_t port) {
    printf("%d\n",ntohs(port));
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  int packet_num = 1;
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("\npacket number: %d\n",packet_num++);
    printf("==========================\n");
    
    libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr*)packet;
    printf("D-MAC\t");
    print_mac(eth->ether_dhost);
    printf("S-MAC\t");
    print_mac(eth->ether_shost);

    if (ntohs(eth->ether_type) == 0x0800) {
        libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)&packet[ETH_LEN];
        printf("D-IP\t");
        print_ip(ip->ip_dst);
        printf("S-IP\t");
        print_ip(ip->ip_src);

        if (ip->ip_p == 0x6) {
            libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)&packet[ETH_LEN + ip->ip_hl*4];
            printf("D-PORT\t");
            print_port(tcp->th_dport);
            printf("S-PORT\t");
            print_port(tcp->th_sport);

            printf("data\t");
            int data_offset = ETH_LEN + ip->ip_hl*4 + tcp->th_off*4;
            for (int i=0; i<10; i++) {
                if (data_offset + i < header->caplen)
                    printf("%02x ",packet[data_offset + i]);
            }
            printf("\n");
        }
    }
    printf("==========================\n\n");
  }

  pcap_close(handle);
  return 0;
}
