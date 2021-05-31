#ifndef __CRAFT_PKT_H__
#define __CRAFT_PKT_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netdb.h>
//#include <linux/ip.h>
//#include <linux/icmp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <pthread.h>

typedef enum {
    UDP  = 0,
    TCP  = 1,
    ICMP = 2
} _protocol_t;

typedef struct _packet_t {
    struct ether_header eth_hdr;
    struct iphdr ip_hdr;
    struct udphdr udp_hdr;
    char payload[8];
    int len;
}  __attribute__((packed)) packet_t;

#endif /* craft_pkt.h */
