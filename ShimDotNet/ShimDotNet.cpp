
/*
 * Copyright (c) 2020 anicca048
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifdef _MSC_VER

#include <WS2tcpip.h>
#include <WinSock2.h>

#else

#include <arpa/inet.h>
#include <netinet/in.h>

#endif

#include <string>
#include <cliext/vector>
#include <cstdint>
#include <cstdlib>
#include <sstream>

#include <pcap/pcap.h>

#include "ShimDotNet.h"
#include "Packets.h"

#include <msclr/marshal_cppstd.h>

// Using ethernet MTU for packet capture size limit.
#define PCAP_PACKET_CAPTURE_LENGTH 1518
// How long to wait for packet read attempt.
#define PCAP_PACKET_READ_TIMEOUT 1000
// Use promisc mode on iface (if supported) 1 for on and 0 for off.
#define PCAP_IFACE_USE_PROMISC_MODE 1

using Packets::IPHdrVer;
using Packets::IPHdrLen;
using Packets::TCPHdrLen;
using Packets::IPV4AddrToStr;
using Packets::IP_Header;
using Packets::TCP_Header;
using Packets::UDP_Header;
using Packets::Ethernet_Header;

using ShimDotNet::L4_PROTOCOL;
using ShimDotNet::IPV4_PACKET;
using ShimDotNet::CaptureEngine;

// Internal function used to convert STL stirng to cstr.
static int strToCSTR(const std::string&, char*, size_t);

CaptureEngine::CaptureEngine()
{
	// Need to load npcap dll instead of wpcap dll if on windows.
	#ifdef _MSC_VER

	SetDllDirectoryA(R"(C:\Windows\System32\Npcap\)");

	#endif

	// Allocate memory for new enginefilter.
	engineFilter = new bpf_program;
}

CaptureEngine::~CaptureEngine()
{
	// Cleanup memory used for enginefilter.
	if (engineFilter)
	{
		delete engineFilter;
		engineFilter = nullptr;
	}
}

int CaptureEngine::genDeviceList()
{
	// Pcap error message buffer with WinPcap overflow protection.
	char pcapErrorBuffer[PCAP_ERRBUF_SIZE * 4];

	// generate libpcap interface list.
	pcap_if_t *deviceList;      // Pcap interface struct for device list.

	// Grab pcap device list and check for retrieval error.
	if (pcap_findalldevs(&deviceList, pcapErrorBuffer) == -1)
	{
		engineError = msclr::interop::marshal_as<System::String^>(pcapErrorBuffer);
		return -1;
	}

	// Clear device name and description lists if already set.
	if (deviceNames.size() != 0)
	{
		deviceNames.clear();
		deviceDescriptions.clear();
	}

	// Create device name and description lists from pcap interface structs.
	for (pcap_if_t * device = deviceList; device != nullptr; device = device->next)
	{
		// Add device name.
		deviceNames.push_back(msclr::interop::marshal_as<System::String^>(device->name));

		// Add device description /w address if either exist.
		if (device->description)
		{
			std::string descriptionStr = device->description;

			for (pcap_addr* addresses = device->addresses; addresses != nullptr; addresses = addresses->next)
			{
				if (addresses->addr->sa_family == AF_INET)
				{
					// Get interface ip as string.
					std::string addrStr = IPV4AddrToStr(addresses->addr);

					// Make sure we didn't get invalid ip.
					if (addrStr == "0.0.0.0")
						continue;

					descriptionStr += (" [ " + addrStr + " ]");
					break;
				}
			}

			deviceDescriptions.push_back(msclr::interop::marshal_as<System::String^>(descriptionStr));
		}
		else
			deviceDescriptions.push_back("");
	}

	// Cleanup memory from pcap interface lookup.
	pcap_freealldevs(deviceList);
	return 0;
}

int CaptureEngine::startCapture(const int deviceIndex, System::String^ CLRfilterStr)
{
	// Make sure we don't open resources without closing them first.
	if (engineHandle)
	{
		engineError = "must stop capture before starting another capture";
		return -1;
	}

	// Convert C# string to c++ string for minimal code chage.
	std::string filterStr = msclr::interop::marshal_as<std::string>(CLRfilterStr);

	// Pcap error message buffer with WinPcap overflow protection.
	char pcapErrorBuffer[PCAP_ERRBUF_SIZE * 4];

	// Convert C++ string to cstr and create pcap device name.
	size_t devNameSize = (deviceNames[deviceIndex]->Length + 1);
	char* pcapDevice = new char[devNameSize];
	strToCSTR(msclr::interop::marshal_as<std::string>(deviceNames[deviceIndex]), pcapDevice, devNameSize);

	bpf_u_int32 deviceNetwork;  // Pcap device network address for filter.
	bpf_u_int32 deviceNetmask;  // Pcap device netmask for filter.

	// Get network and netmask address for filter compilation.
	if (pcap_lookupnet(pcapDevice, &deviceNetwork, &deviceNetmask, pcapErrorBuffer) == -1)
	{
		// Not a critical error, just set these values incase of error.
		deviceNetwork = 0;
		deviceNetmask = PCAP_NETMASK_UNKNOWN;
	}

	// Create capture session handle.
	engineHandle = pcap_open_live(pcapDevice, PCAP_PACKET_CAPTURE_LENGTH,
								  PCAP_IFACE_USE_PROMISC_MODE,
								  PCAP_PACKET_READ_TIMEOUT, pcapErrorBuffer);

	// Free memory.
	delete[] pcapDevice;

	// Ensure no errors occured opening session handle.
	if (!engineHandle)
	{
		engineError = msclr::interop::marshal_as<System::String^>(pcapErrorBuffer);
		return -1;
	}

	// Device must have a supported data link layer type.
	engineDataLink = pcap_datalink(engineHandle);

	switch (engineDataLink)
	{
		// Ethernet.
		case DLT_EN10MB:
		{
			break;
		}
		// RAW IP.
		case DLT_RAW:
		{
			break;
		}
		// Unsupported.
		default:
		{
			engineError = "unsupported device datalink type";
			return -1;
		}
	}

	// Compile and set pcap capture filter (add user filter if exist).
	if (!filterStr.empty() && filterStr != "")
		filterStr = ("(udp or tcp) and " + filterStr);
	else
		filterStr = "(udp or tcp)";

	// Create Pcap filter.
	size_t filterStrSize = (filterStr.length() + 1);
	char* pcapFilter = new char[filterStrSize];
	strToCSTR(filterStr, pcapFilter, filterStrSize);

	// Compile pcap filter and check for error.
	if (pcap_compile(engineHandle, engineFilter, pcapFilter,
					 deviceNetmask, deviceNetwork) == -1)
	{
		engineError = msclr::interop::marshal_as<System::String^>(pcapErrorBuffer);
		// Free memory.
		delete[] pcapFilter;
		return -1;
	}

	// Free memory.
	delete[] pcapFilter;

	// Bind pcap filter to session handle and check for error.
	if (pcap_setfilter(engineHandle, engineFilter) == -1)
	{
		engineError = msclr::interop::marshal_as<System::String^>(pcapErrorBuffer);
		return -1;
	}

	return 0;
}

int CaptureEngine::startCapture(System::String^ deviceName, System::String^ filterStr)
{
	// Check for valid device name.
	int deviceIndex = -1;
	int deviceCount = static_cast<int>(deviceNames.size());

	for (int i = 0; i < deviceCount; i++)
	{
		if (deviceName == deviceNames[i])
		{
			// Device name found.
			deviceIndex = i;
			break;
		}
	}

	if (deviceIndex == -1)
	{
		engineError = "invalid device name";
		return -1;
	}

	return startCapture(deviceName, filterStr);
}

int CaptureEngine::getNextPacket(IPV4_PACKET^% nextPacket)
{
	if (!engineHandle)
	{
		engineError = "must start capture before getting a packet";
		return -1;
	}

	// Get pcap packet and pcap packet header.
	pcap_pkthdr pktHeader;
	const u_char* packet = pcap_next(engineHandle, &pktHeader);

	if (!packet)
		return -1;

	// Offset for internet protocol after DL strip.
	unsigned int ipHdrOff = 0;

	const struct Ethernet_Header* eth_hdr = nullptr;    // Ethernet header ptr.
	const struct IP_Header* ip_hdr = nullptr;			// IP header ptr.
	const struct TCP_Header* tcp_hdr = nullptr; 		// TCP header ptr.
	const struct UDP_Header* udp_hdr = nullptr;			// UDP header ptr.

	uint8_t  ip_ver;            // IP version (4 or 6).
	uint16_t ip_hdr_size;       // IP header size.
	uint16_t tcp_hdr_size;      // TCP header size.

	// Determine offset for IP header based on datalink type.
	switch (engineDataLink)
	{
		// Ethernet.
		case DLT_EN10MB:
		{
			// Check for damaged ethernet packet.
			if (pktHeader.caplen < ETHERNET_HDR_SIZE)
				return -1;

			// Define ethernet header.
			eth_hdr = reinterpret_cast<const struct Ethernet_Header*>(packet);

			// Drop non IPv4 packets.
			if (ntohs(eth_hdr->ether_type) != ETHERNET_TYPE_IPV4)
				return -1;

			// Check for damaged IPV4 packet.
			if (pktHeader.caplen < (ETHERNET_HDR_SIZE + IPV4_HEADER_MIN_LEN))
				return -1;

			// Use ethernet header for ipheader offset.
			ipHdrOff = ETHERNET_HDR_SIZE;
			break;
		}
		// RAW IP.
		case DLT_RAW:
		{
			// Check for damaged IPV4 packet.
			if (pktHeader.caplen < IPV4_HEADER_MIN_LEN)
				return -1;

			// Raw ip has no offset for ip heaser.
			ipHdrOff = 0;
			break;
		}
	}

	// Create IP header and stats from ethernet or raw header.
	ip_hdr = reinterpret_cast<const struct IP_Header*>(packet + ipHdrOff);
	ip_hdr_size = IPHdrLen(ip_hdr);
	ip_ver = IPHdrVer(ip_hdr);

	// Drop non IPv4 (IPv6) packets.
	if (ip_ver != IP_TYPE_V4)
		return -1;

	// Drop packets with invalid IP Header size.
	if (ip_hdr_size < IPV4_HEADER_MIN_LEN)
		return -1;

	// Set shim packet ip address properties.
	nextPacket->source_address = gcnew System::Net::IPAddress(ip_hdr->ip_src.S_un.S_addr);
	nextPacket->destination_address = gcnew System::Net::IPAddress(ip_hdr->ip_dst.S_un.S_addr);

	// Drop packets of unsupported protocols, or compare to connections list.
	if (ip_hdr->ip_p == IPPROTO_TCP)
	{
		// Check for damaged tcp packet.
		if (pktHeader.caplen < (ipHdrOff + IPV4_HEADER_MIN_LEN + TCP_HEADER_MIN_LEN))
			return -1;

		// Define tcp header by offset.
		tcp_hdr = reinterpret_cast<const struct TCP_Header*>(packet + ipHdrOff + ip_hdr_size);
		tcp_hdr_size = TCPHdrLen(tcp_hdr);

		// Drop packets with invalid tcp header size.
		if (tcp_hdr_size < TCP_HEADER_MIN_LEN)
			return -1;

		// Set connection protocol.
		nextPacket->protocol = L4_PROTOCOL::TCP;

		// Set connection ports.
		nextPacket->source_port = ntohs(tcp_hdr->th_sport);
		nextPacket->destination_port = ntohs(tcp_hdr->th_dport);

		// Compute tcp payload wihtout using tcp segment section / option feild.
		nextPacket->payload_size = (ntohs(ip_hdr->ip_len) - (ip_hdr_size + tcp_hdr_size));
	}
	else if (ip_hdr->ip_p == IPPROTO_UDP)
	{
		// check for damaged udp packet.
		if (pktHeader.caplen < (ipHdrOff + IPV4_HEADER_MIN_LEN + UDP_HDR_SIZE))
			return -1;

		// Define udp header by offset.
		udp_hdr = reinterpret_cast<const struct UDP_Header*>(packet + ipHdrOff + ip_hdr_size);

		// Set connection protocol.
		nextPacket->protocol = L4_PROTOCOL::UDP;

		// Set connection ports.
		nextPacket->source_port = ntohs(udp_hdr->uh_sport);
		nextPacket->destination_port = ntohs(udp_hdr->uh_dport);

		// Compute packet payload size.
		nextPacket->payload_size = (ntohs(udp_hdr->uh_ulen) - UDP_HDR_SIZE);
	}
	else
		return -1;

	return 0;
}

int CaptureEngine::getNextPacketStr(System::String^% nextPacketStr)
{
	IPV4_PACKET^ nextPacket;

	if (getNextPacket(nextPacket) == -1)
		return -1;

	// Use sstream to build packet string.
	std::stringstream packSStream;

	// Add protocol.
	if (nextPacket->protocol == L4_PROTOCOL::TCP)
		packSStream << "TCP:";
	else
		packSStream << "UDP:";

	// Add addresses, ports, and payload stats.
	packSStream << msclr::interop::marshal_as<std::string>(nextPacket->source_address->ToString()) << ":"
				<< nextPacket->source_port << ":"
				<< msclr::interop::marshal_as<std::string>(nextPacket->destination_address->ToString()) << ":"
				<< nextPacket->destination_port << ":"
				<< nextPacket->payload_size;

	// Finaly, copy data to string.
	nextPacketStr = msclr::interop::marshal_as<System::String^>(packSStream.str());

	return 0;
}

void CaptureEngine::stopCapture()
{
	// Free compiled filter code if used.
	if (filterSet)
	{
		pcap_freecode(engineFilter);
		filterSet = false;
	}

	// Cleanup after capture session if started.
	if (engineHandle)
	{
		pcap_close(engineHandle);
		engineHandle = nullptr;
	}
}

int CaptureEngine::getDeviceCount()
{
	return static_cast<int>(deviceNames.size());
}

System::String^ CaptureEngine::getDeviceName(const int deviceIndex)
{
	return deviceNames[deviceIndex];
}

System::String^ CaptureEngine::getDeviceDescription(const int deviceIndex)
{
	return deviceDescriptions[deviceIndex];
}

System::String^ CaptureEngine::getLibVersion()
{
	return  msclr::interop::marshal_as<System::String^>(pcap_lib_version());
}

System::String^ CaptureEngine::getEngineError()
{
	return engineError;
}

static int strToCSTR(const std::string& str, char* cstr, size_t size)
{
	// Refuse to access invalid memory.
	if (size != (str.length() + 1))
	{
		return -1;
	}

	int i = 0;

	// Set cstring char by char.
	for (char c : str)
	{
		cstr[i] = c;
		i++;
	}

	// Cstrings must be null terminated.
	cstr[i] = '\0';

	// All good signal.
	return 0;
}
