#include <iostream>
#include <pcap.h>

using namespace std;

class PacketSniffer
{
	private:
		static const int MAX_PACKET_SIZE;
		char errBuff[PCAP_ERRBUF_SIZE];
		//device list and list items of all devices that can be used to sniff traffic
		pcap_if_t *m_deviceList;
		pcap_if_t *m_device;

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
	public: 
		PacketSniffer();
		~PacketSniffer();
		bool Initialize();
		//Try to open the device specified by the user
		bool OpenDevice( int deviceIndex );
		//Listen in on a device, if an exception occurs, return an error code
		bool CaptureNextPacket();
		int GetDeviceCount();
		//Recursively gets all device names and descriptions
		void DisplayAllDevices();
};