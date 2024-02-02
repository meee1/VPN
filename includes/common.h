#ifndef INCLUDES
#define INCLUDES value

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
//#include <cutils/log.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>

#endif

#define LOG_TAG "vpn"

struct ip_hdr {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

#endif