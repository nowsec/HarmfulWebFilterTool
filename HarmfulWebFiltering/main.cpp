#define _CRT_SECURE_NO_WARNINGS
#include "main.h"

#include "PacketFunction.h"
#include "strFunction.h"
#define MAXBUF  0xFFFF
#define STARTHTTPOFFSET 54


int __cdecl main(int argc, char **argv)
{
	bool mal_site_state = false;
	HANDLE handle, console;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	unsigned char site[100];
	char buf[1024] = { 0, };
	FILE *f_log_txt;
	FILE *f_malsite_txt;
	UINT packet_len;
	WINDIVERT_ADDRESS addr;
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
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
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
			if (strncmp((char*)tcppacket + i, "Host", strlen("Host")) == 0)
			{
				mystrcpy(site, tcppacket + i + 5);
				break;
			}
		}


		//prevent mal_site
		/////////////////////////////////////////////////////////////////////////////////////////
		while (!feof(f_malsite_txt))
		{
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
				mal_site_state = true;
				break;
			}
		}
		if (mal_site_state == false)
		{
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to send TCP reset (%d)\n",			GetLastError());
			}
		}
		else
		{
			continue;
		}

		
		putchar('\n');
	}
	return 1;
}