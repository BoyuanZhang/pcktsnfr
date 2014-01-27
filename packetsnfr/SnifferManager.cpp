#include "SnifferManager.h"

SnifferManager::SnifferManager()
{
	m_sniffer = new PacketSniffer();
	//Set default bandwidth recording to false
	m_recordBandwidth = false;
	//Set initial bandwidth count to 0
	m_totalBandwidth = 0;
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
	if( validateDevice( deviceIndex) )
	{
		cout << "About to start listening in on device: " << deviceIndex << endl << endl;
		cout << "Please press esc at any time to stop listening." << endl;
		
		//decrement the deviceIndex by 1 because the packet sniffer uses zero indexing
		return m_sniffer->OpenDevice(deviceIndex-1);
	}

	return false;
}

void SnifferManager::DisplayDeviceInformation( int deviceIndex )
{
	if( validateDevice( deviceIndex ) )
	{
		m_sniffer->DisplayDeviceInformation( deviceIndex-1);
	}
}

void SnifferManager::CloseSession()
{
	//Close the session, and if bandwidth recording was enabled, we out put the total
	//captured bandwidth
	m_sniffer->CloseCurrentSession();

	if( m_recordBandwidth )
		printf( "\nTotal bandwidth usage for this session is: %f MB\n", m_totalBandwidth/1000 );
}

void SnifferManager::ToggleRecord()
{
	if( m_recordBandwidth )
	{
		m_recordBandwidth = false;
		cout << "Bandwidth recording is now off." << endl;
	}
	else
	{
		m_recordBandwidth = true;
		cout << "Bandwidth recording is now on." << endl;
	}
}

void SnifferManager::SetFilter( char* filter )
{
	m_sniffer->SetFilter( filter );
}

void SnifferManager::ClearFilter()
{
	m_sniffer->ClearFilter();
}

bool SnifferManager::GetPacket()
{
	//passing private variable m_totalBandwidth by reference here
	if( m_sniffer->CaptureNextPacket(m_recordBandwidth, m_totalBandwidth))
		return true;

	return false;
}

void SnifferManager::DisplayDevices()
{
	m_sniffer->DisplayAllDevices();
}

bool SnifferManager::validateDevice(int deviceIndex)
{
	if( deviceIndex > 0 && deviceIndex <= m_sniffer->GetDeviceCount() )
		return true;
	else
	{
		cout << "Invalid entry, index entered is out of range!" << endl;
		return false;
	}
}