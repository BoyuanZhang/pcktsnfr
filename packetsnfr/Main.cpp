#include "SnifferClient.h"

#include <iostream>
#include <string>

using namespace std;

int main()
{
	//The client has a handle to the sniffer manager to provide a layer of abstraction
	SnifferClient *client = new SnifferClient();
	 //If we were able to get a handle to at least one network adapter, we go to the main menu
	 //on the client
	if(client->Initialize())
		client->Menu();

	//Sniffer has finnished running, delete it and continue to program exit
	if( client != NULL )
		delete client;
	
	//For debug mode, so the console does not close immediately
	#ifndef DEBUG

	string line;
	cout << "Press any key to exit.";
	getline( cin, line );

	#endif

	return 0;
}
