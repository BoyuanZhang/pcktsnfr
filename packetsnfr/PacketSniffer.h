#include <iostream>
#include "Headers.h"

using namespace std;

class PacketSniffer
{
	private:
		static const int MAX_PACKET_SIZE;
		static const short IP_LENGTH;
		char errBuff[PCAP_ERRBUF_SIZE];
		//filter
		char filterStr[256];
		//device list and list items of all devices that can be used to sniff traffic
		pcap_if_t *m_deviceList;
		pcap_if_t *m_device;
		//holds current devices IPV4 address
		u_char m_deviceIPV4addr[4];
		//pointer to the winpcap packet header structure
		struct pcap_pkthdr *packetHeader;
		//pointer to the data returned in the packet
		const u_char *packetData;
		//handle to the descriptor of the open device instance
		//this structure's functionality is transparent to the user, and is handled by wpcap.dll
		pcap_t *m_deviceHandle;

		int m_deviceCount;

		void DisplayDevices( pcap_if_t *device, int deviceNumber);
		pcap_if_t *GetDevice( int deviceIndex);

		//Returns a character pointer of the conversion from a numerical IP address to a string
		char *iptostr( u_long ip);
		//Returns a character pointer of the conversion from a numerical IP6 address to a string
		char *ip6tostr( struct sockaddr *sockaddr, char *address, int addrlen );
		//Setting filters on packets
		int CompileAndSetIPV4Filter(pcap_if_t *device );
		void PacketHandler( const struct pcap_pkthdr *header, const u_char *data, bool record, double &totalBandwidth );
		void HandleUDPPacket( ipv4hdr *ih);
		void HandleTCPPacket( ipv4hdr *ih);
		void ClearDeviceAddr();

		pcap_addr_t* GetIPV4Addr(pcap_if_t* device);
	public: 
		PacketSniffer();
		~PacketSniffer();
		bool Initialize();
		//Try to open the device specified by the user
		bool OpenDevice( int deviceIndex );
		//Listen in on a device, if an exception occurs, return an error code
		bool CaptureNextPacket( bool record, double &totalBandwidth);
		int GetDeviceCount();
		//Recursively gets all device names and descriptions
		void DisplayAllDevices();
		void DisplayDeviceInformation( int deviceIndex );
		void SetFilter( char* filter );
		void ClearFilter();
		void CloseCurrentSession();
};