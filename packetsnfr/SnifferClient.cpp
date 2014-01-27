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
	int selection;
	bool quit = false;

	DisplayMenu();

	while( !quit )
	{
		cout << "Selection: ";
		cin >> selection;
		//Invalid input validation should occur here.. for now we assume user input a valid numerical value
		switch( selection )
		{
			case 1:
				m_manager->DisplayDevices();
				break;
			case 2:
				cout << "Please select a device to get information on: ";
				cin >> selection;

				m_manager->DisplayDeviceInformation( selection );
				break;
			case 3:
				char filter[50];
				cin.ignore();
				cout << "Please enter a valid filter: ";
				cin.getline( filter, 50);
				m_manager->SetFilter( filter );
				break;
			case 4:
				m_manager->ClearFilter();
				break;
			case 5:
				cout << "Please select a device to listen in on: ";
				cin>> selection;

				//Lets try to open the selected device to listen on it, if it is opened we begin capturing packets
				if(m_manager->OpenDevice( selection ))
				{
					//This logic is on the client level because for now I need to take keyboard input to exit to loop since,
					//I'm not using any threads or events

					//Listen on device until the manager is unable to get the next packet, or the user has pressed escape
					while( m_manager->GetPacket() && !GetAsyncKeyState(VK_ESCAPE) );
					//close and deallocate resources associated with packet capture session
					m_manager->CloseSession();
				}
				break;
			case 6:
				m_manager->ToggleRecord();
				break;
			case 7:
				quit = true;
				break;
			default:
				cout << "Invalid selection, please select indexes only in the menu! " << endl << endl << endl;
				break;
		}

		if( !quit )
			DisplayMenu();
	}
}

void SnifferClient::DisplayMenu()
{
	cout << endl;
	cout << "Menu Options ----------------" << endl;
	cout << "1: Display all devices " << endl;
	cout << "2: Display advanced information on device" << endl;
	cout << "3: Set a filter for packet capture" << endl;
	cout << "4: Clear packet filter" << endl;
	cout << "5: Begin Capturing packets on device" << endl;
	cout << "6: Toggle Bandwidth capture" << endl;
	cout << "7: Quit"  << endl;
}