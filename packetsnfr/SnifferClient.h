#include "SnifferManager.h"

#include <iostream>
#include <Windows.h>

using namespace std;

//Simple command prompt client for testing purposes
class SnifferClient {
	private:
		//handle to the sniffer manager
		SnifferManager *m_manager;

		void DisplayMenu();
	public:
		SnifferClient();
		~SnifferClient();
		
		bool Initialize();
		//Main menu
		void Menu();
};