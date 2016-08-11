#include "main.h"

void PacketIpInit(PWINDIVERT_IPHDR packet);
void PacketIpTcpInit(PTCPPACKET packet);
void PacketIpIcmpInit(PICMPPACKET packet);
void PacketIpv6Init(PWINDIVERT_IPV6HDR packet);
void PacketIpv6TcpInit(PTCPV6PACKET packet);
void PacketIpv6Icmpv6Init(PICMPV6PACKET packet);
