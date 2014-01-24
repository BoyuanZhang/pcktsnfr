#include "pcap.h"

#define SIZE_ETHERNET 14

typedef struct ethhdr{
	u_char dest[6];
	u_char src[6];
	u_short type;
}ethhdr;

typedef struct ipaddr{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ipaddr;

typedef struct ipv4hdr {
	u_char ver_ihl;	//4 bit version + 4 bit internet headerlength
	u_char dscp_ecn; // 6 bit differientiated services + 2 bit congestion notification
	u_short len; //2 byte length
	u_short identification; // 2 byte identification
	u_short flags_fo; //flags 3 bits + 13 bit offset
	u_char ttl; //1 byte time to live
	u_char protocol; // 1 byte protocol
	u_short hcs; //2 byte checksum
	ipaddr src; //4 byte source ip address
	ipaddr dst; //4 byte destination ip address
	u_int opt_pad;	//options and padding
}ipv4hdr;

typedef struct udphdr{
	u_short srcport;
	u_short dstport;
	u_short len;
	u_short checksum;
}udphdr;

typedef struct tcphdr{
	u_short srcport;
	u_short dstport;
	u_int sequence;
	u_int acknowledgement;
	u_char data_offset:4;	//number of 32 bit words in the TCP header. Indicates where the data begins, length is always a multiple of 32 bits
	u_char reserved:3; //for future use, all bits should be set to 0

	//Control bit flags
	u_char flag_ns:1; //ECN-nonce concealment protection
	u_char flag_cwr:1; //Congestion window reduced flag
	u_char flag_ece:1; //ECN-Echo flag 
	u_char flag_urg:1; //Urgent pointer field
	u_char flag_psh:1; //Asks to push buffered data to receiving application
	u_char flag_rst:1; //Reset connection
	u_char flag_syn:1; //synchronize sequence numbers Only the first packet sent from each end should have this flag set. 
					   //Some other flags change meaning based on this flag, and some are only valid for when it is set, and others when it is clear.
	u_char flag_fin:1; //No more data from sender

	u_short window_size;
	u_short checksum;
	u_short urgent_pointer; //If flag_urg is set
	
	//Last field Options is set by the data offset field.

}tcphdr;