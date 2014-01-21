#include "SnifferManager.h"

#include <iostream>
#include <Windows.h>

using namespace std;

class SnifferClient {
	private:
		//handle to the sniffer manager
		SnifferManager *m_manager;
	public:
		SnifferClient();
		~SnifferClient();
		
		bool Initialize();
		//Main menu
		void Menu();
};