#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

struct Ethernet {
    const u_char* d_mac;
    const u_char* s_mac;
    uint16_t type;
};

struct IP {
    const u_char* d_ip;
    const u_char* s_ip;
    uint8_t protocol;
    uint8_t ip_header_size;
    uint16_t total_size;
};

struct TCP {
    uint16_t d_port;
    uint16_t s_port;
    uint8_t header_length;
};

Ethernet make_eth_struct(const u_char* packet) {
    Ethernet eth;
    eth.d_mac = &packet[0];
    eth.s_mac = &packet[6];
    eth.type = (packet[12] << 8) | packet[13];

    return eth;
}

IP make_ip_struct(const u_char* packet) {
    IP ip;
    ip.s_ip = &packet[12];
    ip.d_ip = &packet[16];
    ip.protocol = packet[9];
    ip.ip_header_size = (packet[0] & 0x0f) << 2;
    ip.total_size = (packet[2] << 8) | packet[3];

    return ip;
}

TCP make_tcp_struct(const u_char* packet) {
    TCP tcp;
    tcp.s_port = (packet[0] << 8) | packet[1];
    tcp.d_port = (packet[2] << 8) | packet[3];
    tcp.header_length = (packet[12] >> 4) << 2;

    return tcp;
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* n) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", n[0], n[1], n[2], n[3], n[4], n[5]);
}

int print_eth(Ethernet eth) {
    printf("S-MAC ");
    print_mac(eth.s_mac);
    printf("D-MAC ");
    print_mac(eth.d_mac);

    // is IP?
    if (eth.type == 0x0800)
        return 1;
    return 0;
}

void print_ip_addr(const u_char* n) {
    printf("%d.%d.%d.%d\n", n[0], n[1], n[2], n[3]);
}

int print_ip(IP ip) {
    printf("S-IP ");
    print_ip_addr(ip.s_ip);
    printf("D-IP ");
    print_ip_addr(ip.d_ip);

    // is TCP?
    if (ip.protocol == 0x06)
        return 1;
    return 0;
}

void print_tcp(TCP tcp) {
    printf("S-PORT ");
    printf("%d\n", tcp.s_port);
    printf("D-PORT ");
    printf("%d\n", tcp.d_port);
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

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    int ethernet_header_size = 14;
    Ethernet eth = make_eth_struct(packet);

    if (print_eth(eth)) {    // if IP protocol
        IP ip = make_ip_struct(&packet[ethernet_header_size]);
        if (print_ip(ip)) {  // if tcp protocol
            int tcp_offset = ethernet_header_size + ip.ip_header_size;
            TCP tcp = make_tcp_struct(&packet[tcp_offset]);
            print_tcp(tcp);

            printf("data ");
            int data_offset = tcp_offset + tcp.header_length;
            for (int i=0; i<10; i++) {   // if packet has tcp data
                if (header->caplen > (data_offset + i)) {
                    printf("%02x ", packet[ethernet_header_size + ip.ip_header_size + tcp.header_length + i]);
                }
            }
        }
    }

    printf("\n-----------------------\n");
  }

  pcap_close(handle);
  return 0;
}
