#include "PacketSniffer.h"

//Eventually all standard output statements should be headed to an output class, but for now I'll just stick 
//the outputs in here
using namespace std;

const int PacketSniffer::MAX_PACKET_SIZE = 65536;

PacketSniffer::PacketSniffer ()
{
	m_deviceCount = 0;
}

PacketSniffer::~PacketSniffer()
{
	//Delete device list
	pcap_freealldevs( m_deviceList );
}

bool PacketSniffer::Initialize()
{
	//pcap error buffer

	if( pcap_findalldevs_ex( PCAP_SRC_IF_STRING, NULL, &m_deviceList, errBuff ) == -1 )
	{
		cout << "Error in pcap_findalldevs_ex: " << errBuff;
		return false;
	}

	//were devices found?
	if( m_deviceList == NULL )
	{
		cout << "No network adapters could be found! Make sure you have WinPCap installed. " << endl;
		return false;
	}

	//Great! Now lets set the total number of devices that were returned
	m_device = m_deviceList;
	while( m_device )
	{
		m_deviceCount++;
		m_device = m_device->next;
	}

	return true;
}

bool PacketSniffer::OpenDevice( int deviceIndex)
{
	m_device = GetDevice( deviceIndex );
	//if a valid device was returned we begin packet capturing
	if( m_device )
	{
		//open the device
		m_deviceHandle = pcap_open( m_device->name,
									MAX_PACKET_SIZE,
									PCAP_OPENFLAG_PROMISCUOUS,
									1000, //<-- the timeout we set to 1 second
									NULL, //<-- authentication on the remote machine
									errBuff);

		if( m_deviceHandle )
		{
			cout << "Capture session started on device: " << m_device->name << endl;
			return true;
		}
		else
		{
			cout << "Unable to open device: " << m_device->name << endl;
		}
	}

	return false;
}

bool PacketSniffer::CaptureNextPacket()
{	
	int retValue = pcap_next_ex( m_deviceHandle, &packetHeader, &packetData );
	
	//output packet information... for now just output the length
	if( retValue == 1 )
	{
		cout << "Captured packet with length: " << packetHeader->len << endl;
	}
	else if( retValue == -1 )
	{
		cout << "Error reading the packet: " << pcap_geterr( m_deviceHandle);
		return false;
	}

	return true;
}

pcap_if_t* PacketSniffer::GetDevice( int deviceIndex)
{
	m_device = m_deviceList;
	//traverse to the desired index of the device we will return
	for( int i = 0; m_device!=NULL; i++)
	{
		if( i == deviceIndex)
			return m_device;

		m_device = m_device->next;
	}

	//we didn't find the corresponding device
	return NULL;
}

int PacketSniffer::GetDeviceCount()
{
	return m_deviceCount;
}

void PacketSniffer::DisplayAllDevices()
{
	//begin at head of the device list
	m_device = m_deviceList;
	
	DisplayDevices( m_device, 1 );
}

//Go through linked list of devices to display the name and description of each device
void PacketSniffer::DisplayDevices( pcap_if_t* device, int deviceNumber)
{
	if( device != NULL )
	{
		cout << "Device #: " << deviceNumber << "--------" << endl;
		cout << "Device name: " << device->name << endl;
		cout << "Device Description: " << device->description << endl;
		cout << endl;
	}
	if( device->next != NULL )
		DisplayDevices( device->next, deviceNumber+1 );
}