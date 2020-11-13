
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
#include <cliext/vector>

#include <pcap/pcap.h>

namespace ShimDotNet
{
	// Describes layer 4 protocol type.
	public enum class L4_PROTOCOL
	{
		UDP,
		TCP
	};

	// Holds relavent packet info for apps using Shim.
	public ref class IPV4_PACKET
	{
	public:
		System::Net::IPAddress^ source_address;
		System::Net::IPAddress^ destination_address;
		L4_PROTOCOL protocol;
		System::UInt16 source_port;
		System::UInt16 destination_port;
		System::UInt32 payload_size;
	};

	// Shim's core, interfaces with libpcap to make packet capture easier.
	public ref class CaptureEngine
	{
		public:
			// Default ctor and dtor, manage dynamic memory used by class.
			CaptureEngine();
			~CaptureEngine();
			// Generates device name and description lists.
			int genDeviceList();
			// Does packet capture init.
			int startCapture(const int, System::String^);
			int startCapture(System::String^, System::String^);
			// Gets the next packet from capture engine.
			int getNextPacket(IPV4_PACKET^%);
			// Gets the next packet from capture engine as a shim packet string.
			int getNextPacketStr(System::String^%);
			// Cleans up after packet capture init.
			void stopCapture();
	
			// Functions for accessing device names and descriptions.
			int getDeviceCount();
			System::String^ getDeviceName(const int);
			System::String^ getDeviceDescription(const int);
			// Returns the libpcap / npcap library version string.
			System::String^ getLibVersion();
			// Gets the capture session error if there is one.
			System::String^ getEngineError();
		private:
			// Libpcap sesison handle.
			pcap_t* engineHandle = nullptr;
			// Libpcap bpf compiled capture filter.
			bpf_program* engineFilter = nullptr;
			bool filterSet = false;
			// DataLink type for device used during startCapture().
			int engineDataLink;
			
			// List of libpcap interface names.
			cliext::vector<System::String^> deviceNames;
			// List of libpcap interface descriptions and addresses.
			cliext::vector<System::String^> deviceDescriptions;
			// Holds error messages set during CEngine and libpcap operations.
			System::String^ engineError;
	};
}
