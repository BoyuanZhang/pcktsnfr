#include "SnifferManager.h"

SnifferManager::SnifferManager()
{
	m_sniffer = new PacketSniffer();
}

SnifferManager::~SnifferManager()
{
	if( m_sniffer != NULL )
		delete m_sniffer;
}

bool SnifferManager::Initialize()
{
	if( m_sniffer->Initialize() )
		return true;

	return false;
}

//Validates if the request device to be listened on exists, if it does then listen to all traffic on that device
bool SnifferManager::OpenDevice(int deviceIndex)
{	
	if( deviceIndex > 0 && deviceIndex <= m_sniffer->GetDeviceCount() )
	{
		cout << "About to start listening in on device: " << deviceIndex << endl;
		
		//decrement the deviceIndex by 1 because the packet sniffer uses zero indexing
		return m_sniffer->OpenDevice(deviceIndex-1);
	}
	else
		cout << "Invalid entry, index entered is out of range!" << endl;

	return false;
}

bool SnifferManager::GetPacket()
{
	if( m_sniffer->CaptureNextPacket())
		return true;

	return false;
}

void SnifferManager::DisplayDevices()
{
	m_sniffer->DisplayAllDevices();
}