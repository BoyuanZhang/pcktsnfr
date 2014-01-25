By: Boyuan Zhang

C++ Packet sniffer for processing network traffic.

	- Is able to sniff packets on a network interface (only returns packet length at the moment)
	
	- Able to list advanced information of all network device interfaces
		- Address family information (IPV4, IPV6)
			- Address family name, IP address in network, Net mask, Subnet, Broadcast address
			  Destination Address
	
	- Able to filter packets with a user input filtering expression for example, ("ip and tcp") expression to
	  keep only packets that are both TCP and IPV4
	  
	- Implemented interepretation of the following protocols: TCP, UDP

Project started for the learning purposes of WinPcap, and network programming
