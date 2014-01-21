#include "PacketSniffer.h"
//the outputs in here
using namespace std;

const int PacketSniffer::MAX_PACKET_SIZE = 65536;
const short PacketSniffer::IP_LENGTH = 16;

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

void PacketSniffer::DisplayDeviceInformation( int deviceNumber )
{
	m_device = GetDevice( deviceNumber);

	if( m_device )
	{
		//Pointer to the list of addresses
		pcap_addr_t *address;

		cout << "Device name: " << m_device->name << endl;
		cout << "Loopback Address: ";
		if( (m_device->flags & PCAP_IF_LOOPBACK) == 0 )
			cout << "no" << endl;
		else
			cout << "yes" << endl;
		for( address = m_device->addresses; address; address = address->next )
		{
			switch( address->addr->sa_family )
			{
				//IPV4 family, note destination address might be null if device interface isn't a point-to-point interface
				case AF_INET:
					cout << "Address Family Name: AF_INET" << endl;
					if( address->addr)
						cout << "Address: " << iptostr( ((struct sockaddr_in*)address->addr)->sin_addr.S_un.S_addr) << endl;
					if( address->netmask)
						cout << "Netmask: " << iptostr( ((struct sockaddr_in*)address->netmask)->sin_addr.S_un.S_addr) << endl;
					if( address->broadaddr)
						cout << "Broadcast Address: " << iptostr( ((struct sockaddr_in*)address->broadaddr)->sin_addr.S_un.S_addr) << endl;
					if( address->dstaddr)
						cout << "Destination Address: " << iptostr( ((struct sockaddr_in*)address->dstaddr)->sin_addr.S_un.S_addr) << endl;
					break;
				//IPV6 family
				case AF_INET6:
					char ip6str[128];
					cout << "Address Family Name: AF_INET6" << endl;
					if( address->addr )
						cout << "Address: " << ip6tostr( address->addr, ip6str, sizeof( ip6str ) ) << endl;
					break;
				default:
					cout << "Address family unknown";
					break;
			}
		}
	}
}

char* PacketSniffer::iptostr( u_long ip)
{
    static char output[IP_LENGTH];
    u_char *p;

	//ip address converted to an unsigned character pointer gives the network address
	//in the first four buckets
    p = (u_char *)&ip;
    sprintf_s(output, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

	return output;
}

//code here taken from winpcap.org for the conversion from an ipv6 address to a string
//this uses the Ws2_32.lib, so the library must be added to additional dependencies in the project
char* PacketSniffer::ip6tostr(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif

    if(getnameinfo(sockaddr, 
        sockaddrlen, 
        address, 
        addrlen, 
        NULL, 
        0, 
        NI_NUMERICHOST) != 0) address = "getnameinfo in ip6tostr failed";

    return address;
}

