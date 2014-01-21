#include "SnifferClient.h"

SnifferClient::SnifferClient()
{
	m_manager = new SnifferManager();
}

SnifferClient::~SnifferClient()
{
	if( m_manager != NULL)
		delete m_manager;
}

bool SnifferClient::Initialize()
{
	if( m_manager->Initialize() )
		return true;

	return false;
}

void SnifferClient::Menu()
{
	m_manager->DisplayDevices();

	int index;
	cout << "Please select a device from the list above to listen in on: ";
	cin>> index;

	//Invalid input validation should occur here.. for now we assume user input a valid numerical value

	//Lets try to open the selected device to listen on it, if it is opened we begin capturing packets
	if(m_manager->OpenDevice( index ))
	{
		//Listen on device until the manager is unable to get the next packet, or the user has pressed escape
		while( m_manager->GetPacket() && !GetAsyncKeyState(VK_ESCAPE) )
		{

		}
	}
}