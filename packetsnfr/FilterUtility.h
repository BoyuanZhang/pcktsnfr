namespace FilterUtility
{
	//default filter
	const char* filter_IP4TCP = "ip and tcp";

	void filter_TCPONPORT( char* port, char* result )
	{
		char* filter_TCPSRCPORT = "tcp src port ";
		//append the tcp src port filter onto the result
		for( int i = 0; i< (int)strlen(filter_TCPSRCPORT); i++)
		{
			*result = filter_TCPSRCPORT[i];
			result++;
		}
		//append the actual port to be filtered on to the result
		for( int i = 0; i< (int)strlen(port); i++)
		{
			*result = port[i];
			result++;
		}

		//null terminate filter
		*result = '\0';
	}
}