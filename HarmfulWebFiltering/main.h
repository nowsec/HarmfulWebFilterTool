#pragma once

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

/*
* Pre-fabricated packets.
*/
typedef struct iptcp_hdr TCPPACKET, *PTCPPACKET;
typedef struct ip6tcp_hdr TCPV6PACKET, *PTCPV6PACKET;
typedef struct ipicmp_hdr ICMPPACKET, *PICMPPACKET;
typedef struct ipicmp6_hdr ICMPV6PACKET, *PICMPV6PACKET;

typedef struct iptcp_hdr
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

typedef struct ip6tcp_hdr
{
	WINDIVERT_IPV6HDR ipv6;
	WINDIVERT_TCPHDR tcp;
} TCPV6PACKET, *PTCPV6PACKET;

typedef struct ipicmp_hdr
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_ICMPHDR icmp;
	UINT8 data[];
} ICMPPACKET, *PICMPPACKET;

typedef struct ipicmp6_hdr
{
	WINDIVERT_IPV6HDR ipv6;
	WINDIVERT_ICMPV6HDR icmpv6;
	UINT8 data[];
} ICMPV6PACKET, *PICMPV6PACKET;
