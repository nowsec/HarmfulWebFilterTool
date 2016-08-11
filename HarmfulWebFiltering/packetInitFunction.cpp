#include "main.h"
#include "PacketFunction.h"

void PacketIpInit(PWINDIVERT_IPHDR packet)
{
	memset(packet, 0, sizeof(WINDIVERT_IPHDR));
	packet->Version = 4;
	packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->Id = ntohs(0xDEAD);
	packet->TTL = 64;
}

/*
* Initialize a TCPPACKET.
*/
void PacketIpTcpInit(PTCPPACKET packet)
{
	memset(packet, 0, sizeof(TCPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Length = htons(sizeof(TCPPACKET));
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* Initialize an ICMPPACKET.
*/
void PacketIpIcmpInit(PICMPPACKET packet)
{
	memset(packet, 0, sizeof(ICMPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Protocol = IPPROTO_ICMP;
}

/*
* Initialize a PACKETV6.
*/
void PacketIpv6Init(PWINDIVERT_IPV6HDR packet)
{
	memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));
	packet->Version = 6;
	packet->HopLimit = 64;
}

/*
* Initialize a TCPV6PACKET.
*/
void PacketIpv6TcpInit(PTCPV6PACKET packet)
{
	memset(packet, 0, sizeof(TCPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));
	packet->ipv6.NextHdr = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* Initialize an ICMP PACKET.
*/
void PacketIpv6Icmpv6Init(PICMPV6PACKET packet)
{
	memset(packet, 0, sizeof(ICMPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.NextHdr = IPPROTO_ICMPV6;
}