#include "PacketSniffer.h"

class SnifferManager {
	private:
		//Handle to the packet sniffer that this class manages
		PacketSniffer *m_sniffer;

		bool validateDevice(int deviceIndex);
	public:
		SnifferManager();
		~SnifferManager();

		//Tries to initialize the packet sniffer, returns false if an error occurs
		bool Initialize();
		//Tell the packet sniffer to listen in on this device index, if an exception occurs return the given error code
		bool GetPacket();
		bool OpenDevice( int deviceIndex );
		void DisplayDevices();
		void DisplayDeviceInformation( int deviceIndex);
};