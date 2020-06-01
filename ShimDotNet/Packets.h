
#pragma once

#ifdef _MSC_VER

#include <WS2tcpip.h>
#include <WinSock2.h>

#else

#include <arpa/inet.h>
#include <netinet/in.h>

#endif

#include <string>
#include <cstdint>

#define ETHERNET_HDR_SIZE 14      // Ethernet headers are always 14 bytes.
#define ETHERNET_ADDR_LEN 6       // Ethernet mac addresses are always 6 bytes.
#define ETHERNET_TYPE_IPV4 0x0800 // IPv4 code in ethernet type section.

#define IP_TYPE_V4 4              // IPv4 version number for header check.
#define IPV4_HEADER_MIN_LEN 20    // Minimum byte size of ipv4 header.

#define TCP_HEADER_MIN_LEN 20
#define UDP_HDR_SIZE 8            // UDP header is always 8 bytes.

namespace Packets
{
    // Ethernet header object for packet processing.
    struct Ethernet_Header
    {
        uint8_t  ether_dhost[ETHERNET_ADDR_LEN];    // Destination mac address.
        uint8_t  ether_shost[ETHERNET_ADDR_LEN];    // Source mac address.
        uint16_t ether_type;                        // Protocol (IP, arp).
    };

    // IP header object for packet processing.
    struct IP_Header
    {
        uint8_t  ip_vhl;        // IP version and header length.
        uint8_t  ip_tos;        // IP packet type of service.
        uint16_t ip_len;        // IP packet length.
        uint16_t ip_id;         // IP packet identification.
        uint16_t ip_off;        // IP fragment offset field.
        uint8_t  ip_ttl;        // IP packet time to live.
        uint8_t  ip_p;          // packet transmission layer protocol.
        uint16_t ip_sum;        // IP packet checksum.
        struct in_addr ip_src;  // IP source address.
        struct in_addr ip_dst;  // IP destination address.
    };

    // TCP header object for packet processing.
    struct TCP_Header
    {
        uint16_t th_sport;  // TCP source port.
        uint16_t th_dport;  // TCP destination port.
        uint32_t th_seq;    // TCP stream packet sequence number.
        uint32_t th_ack;    // TCP stream packet acknowledgement number.
        uint8_t  th_offx2;  // TCP packet data offset and reserved section.
        uint8_t  th_flags;  // TCP stream packet flags.
        uint16_t th_win;    // TCP stream packet window.
        uint16_t th_sum;    // TCP packet checksum.
        uint16_t th_urp;    // TCP stream packet urgent pointer.
    };

    // UDP header object for packet processing.
    struct UDP_Header
    {
        uint16_t uh_sport;  // UDP source port.
        uint16_t uh_dport;  // UDP destination port.
        uint16_t uh_ulen;   // UDP packet length.
        uint16_t uh_sum;    // UDP packet checksum.
    };

    // IP version calculator.
    inline uint8_t IPHdrVer(const IP_Header *&ipHdr)
    {
        return ((ipHdr->ip_vhl & 0xf0) >> 4);    // First nibble has version.
    }
    
    // IP header length calculator.
    inline uint16_t IPHdrLen(const IP_Header *&ipHdr)
    {
        return ((ipHdr->ip_vhl & 0x0f) * 4);    // Second nibble has length.
    }

    // TCP header length calculator.
    inline uint16_t TCPHdrLen(const TCP_Header *&tcpHdr)
    {
        return (((tcpHdr->th_offx2 & 0xf0) >> 4) * 4); // Nibble 1 has len.
    }

	// Converts dot notation string into ipv4 address.
    inline in_addr strToIPV4Addr(std::string IP)
    {
        in_addr ipStruct;
        inet_pton(AF_INET, IP.c_str(), &ipStruct);
        return ipStruct;
    }

	// Converts ipv4 address into dot notation string.
    inline std::string IPV4AddrToStr(in_addr IP)
    {
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &IP, ipStr, INET_ADDRSTRLEN);
        return ipStr;
    }

	inline std::string IPV4AddrToStr(sockaddr* SIP)
	{
		return IPV4AddrToStr((reinterpret_cast<sockaddr_in*>(SIP))->sin_addr);
	}
}
