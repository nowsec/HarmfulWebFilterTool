#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"
#include "head.h"
#define MAXBUF  0xFFFF
#define STARTHTTPOFFSET 54
/*
* Pre-fabricated packets.
*/
typedef struct iptcp_hdr TCPPACKET, *PTCPPACKET;
typedef struct ip6tcp_hdr TCPV6PACKET, *PTCPV6PACKET;
typedef struct ipicmp_hdr ICMPPACKET, *PICMPPACKET;
typedef struct ipicmp6_hdr ICMPV6PACKET, *PICMPV6PACKET;

/*
* Prototypes.
*/

void PacketIpTcpInit(PTCPPACKET packet);
void PacketIpIcmpInit(PICMPPACKET packet);
void PacketIpv6Init(PWINDIVERT_IPV6HDR packet);
void PacketIpv6TcpInit(PTCPV6PACKET packet);
void PacketIpv6Icmpv6Init(PICMPV6PACKET packet);
void mystrcpy(unsigned char *dest, unsigned char *src);
char *findStr(unsigned char *str1, char *str2);
/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
	HANDLE handle, console;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	unsigned char site[100];
	char buf[1024] = { 0, };
	FILE *f_log_txt;
	FILE *f_malsite_txt;
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;
	TCPPACKET reset0;
	PTCPPACKET reset = &reset0;
	unsigned char *tcppacket;


	// Initialize all packets.
	PacketIpTcpInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;

	// Get console for pretty colors.
	console = GetStdHandle(STD_OUTPUT_HANDLE);

	// Divert traffic matching the filter:
	handle = WinDivertOpen("outbound and tcp.PayloadLength > 0 and tcp.DstPort == 80", WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main loop:
	while (TRUE)
	{
		f_log_txt = fopen("log.txt", "a");
		f_malsite_txt = fopen("mal_site.txt", "r");
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		// Print info about the matching packet.
		WinDivertHelperParsePacket(packet, packet_len, &ip_header,
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
			&udp_header, NULL, &payload_len);
		if (ip_header == NULL && ipv6_header == NULL) continue;
		tcppacket = (unsigned char*)malloc(packet_len);
		memcpy(tcppacket, packet, packet_len);

		//get host
		for (int i = STARTHTTPOFFSET; i < packet_len; i++)
		{
			if (tcppacket[i] == 'H' && tcppacket[i + 1] == 'o' && tcppacket[i + 2] == 's' && tcppacket[i + 3] == 't')
			{
				mystrcpy(site, tcppacket + i + 5);
				break;
			}
		}


		//prevent mal_site
		/////////////////////////////////////////////////////////////////////////////////////////
		while (!feof(f_malsite_txt))
		{
			//read(f_malsite_txt, buf, 1024);
			fgets(buf, 1024, f_malsite_txt);
			for (int i = 0; i < sizeof(buf); i++)
			{
				if (buf[i] == 10)
				{
					buf[i] = 0;
					break;
				}
			}
			if (findStr(site, buf))
			{
				UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
				UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
				printf("BLCOK! site : %s ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", buf,
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				fprintf(f_log_txt, "BLCOK! site : %s ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", buf,
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				fclose(f_log_txt);
				break;
			}
		}
		continue;

		if (!WinDivertSend(handle, (PVOID)reset, sizeof(TCPPACKET),
			&send_addr, NULL))
		{
			fprintf(stderr, "warning: failed to send TCP reset (%d)\n",
				GetLastError());
		}


		// Dump packet info: 
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		fputs("BLOCK ", stdout);
		SetConsoleTextAttribute(console,
			FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		if (ip_header != NULL)
		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
		}

		if (tcp_header != NULL)
		{
			printf("tcp.SrcPort=%u tcp.DstPort=%u tcp.Flags=",
				ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort));
			if (tcp_header->Fin)
			{
				fputs("[FIN]", stdout);
			}
			if (tcp_header->Rst)
			{
				fputs("[RST]", stdout);
			}
			if (tcp_header->Urg)
			{
				fputs("[URG]", stdout);
			}
			if (tcp_header->Syn)
			{
				fputs("[SYN]", stdout);
			}
			if (tcp_header->Psh)
			{
				fputs("[PSH]", stdout);
			}
			if (tcp_header->Ack)
			{
				fputs("[ACK]", stdout);
			}
			putchar(' ');

			if (ip_header != NULL)
			{
				reset->ip.SrcAddr = ip_header->DstAddr;
				reset->ip.DstAddr = ip_header->SrcAddr;
				reset->tcp.SrcPort = tcp_header->DstPort;
				reset->tcp.DstPort = tcp_header->SrcPort;
				reset->tcp.SeqNum =
					(tcp_header->Ack ? tcp_header->AckNum : 0);
				reset->tcp.AckNum =
					(tcp_header->Syn ?
					htonl(ntohl(tcp_header->SeqNum) + 1) :
					htonl(ntohl(tcp_header->SeqNum) + payload_len));

				WinDivertHelperCalcChecksums((PVOID)reset, sizeof(TCPPACKET),0);

				memcpy(&send_addr, &recv_addr, sizeof(send_addr));
				send_addr.Direction = !recv_addr.Direction;
				if (!WinDivertSend(handle, (PVOID)reset, sizeof(TCPPACKET),
					&send_addr, NULL))
				{
					fprintf(stderr, "warning: failed to send TCP reset (%d)\n",
						GetLastError());
				}
			}
		}
		putchar('\n');
	}
	return 1;
}
