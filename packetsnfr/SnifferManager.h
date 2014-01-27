#include "PacketSniffer.h"

class SnifferManager {
	private:
		//Handle to the packet sniffer that this class manages
		PacketSniffer *m_sniffer;
		bool m_recordBandwidth;
		bool validateDevice(int deviceIndex);
		//Total bandwidth in KB
		double m_totalBandwidth; 
	public:
		SnifferManager();
		~SnifferManager();

		//Tries to initialize the packet sniffer, returns false if an error occurs
		bool Initialize();
		void ToggleRecord();
		//Tell the packet sniffer to listen in on this device index, if an exception occurs return the given error code
		bool GetPacket();
		bool OpenDevice( int deviceIndex );
		void DisplayDevices();
		void DisplayDeviceInformation( int deviceIndex);
		void SetFilter( char* filter );
		void ClearFilter();
		void CloseSession();
};