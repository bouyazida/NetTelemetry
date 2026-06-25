
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <pcap.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <Winsock2.h>
#include <vector>
#include <sql.h>
#include <sqlext.h>
#include <windows.h>
#include <sqltypes.h>





#define SQL_RESULT_LEN 240
#define SQL_RETURN_CODE_LEN 1000


using namespace std;

#define MAX_PRINT 80
#define MAX_LINE 16
int totale_bytes = 0;
int totale_packet = 0;

#ifdef _WIN32
#include <tchar.h>

BOOL LoadNpcapDlls()
{
	TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

struct ip_header {
    u_char  ver_ihl; // Version (4 bits) + IP header length (4 bits)
    u_char  tos;     // Type of service 
    u_short tlen;    // Total length 
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;      // Time to live
    u_char  proto;    // Protocol
    u_short crc;      // Header checksum
    ip_address  saddr; // Source address
    ip_address  daddr; // Destination address
    u_int  op_pad;     // Option + Padding
};

struct udp_header {
    u_short sport; // Source port
    u_short dport; // Destination port
    u_short len;   // Datagram length
    u_short crc;   // Checksum
};


struct protocole {
    int packet_count = 0;
	int byte_count = 0;
	float bits_per_sec = 0.0f;
	string proto_name = "";
};

struct flow {
	float flow_time = 0.0f;
	int throughtput = 0;
	float flow_effeciency = 0.0f;
	int flow_load = 0;
};

//In the telemetry i need to measure each metric given
//First lets intoduce packets as a structure so we can capture each packet and mesure each metric

struct packet {
	int p_size = 0;
	
	string src_ip = "";
	string dst_ip = "";
	
	int tcp_port = 0;
	int udp_port = 0;

	//protocol statistics and flow both need multiple variables so they are both there separate struct
	protocole prot_stats;
	flow flow_metrics;
	
	//these last two are both percentages so they need to be float
	float retransmission = 0.0f;
	float latency = 0.0f;

    string host_name = "";
};

struct handler_state {
    struct timeval ts;
    SQLHANDLE stmt;
};
 void packet_handler(u_char* state,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data) {
    ip_header* ih;
    u_int ip_len;
    udp_header* uh;
    u_short sport, dport;
    handler_state* hs = (handler_state*)state;
    struct timeval* old_ts = &hs->ts;    u_int delay;
    LARGE_INTEGER Bps, Pps;
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;
    packet pac;

    //accumulate
    totale_bytes += header->len;
    totale_packet++;

    // Calculate the delay in microseconds from the last sample. This value
     // is obtained from the timestamp that the associated with the sample.
    delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000
        - old_ts->tv_usec + header->ts.tv_usec;

    // Convert the timestamp to readable format 
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    if (delay < 1000000) return; 

    // Print timestamp
    printf("%s ", timestr);

    
   //store current timestamp
    old_ts->tv_sec = header->ts.tv_sec;
    old_ts->tv_usec = header->ts.tv_usec;

    //compute
    Bps.QuadPart = totale_bytes * 8;
    Pps.QuadPart = totale_packet;

    ih = (ip_header*)(pkt_data + 14);
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header*)((u_char*)ih + ip_len);
    sport = ntohs(uh->sport);
    dport = ntohs(uh->dport);

    //fill the pac
    pac.p_size = header->len;
    pac.src_ip = to_string(ih->saddr.byte1) + "." + to_string(ih->saddr.byte2) + "." + to_string(ih->saddr.byte3) + "." + to_string(ih->saddr.byte4);
    pac.dst_ip = to_string(ih->daddr.byte1) + "." + to_string(ih->daddr.byte2) + "." + to_string(ih->daddr.byte3) + "." + to_string(ih->daddr.byte4);
    pac.udp_port = dport;
    pac.prot_stats.bits_per_sec = (float)Bps.QuadPart;
    pac.prot_stats.packet_count = (int)Pps.QuadPart;
    pac.latency = (float)delay;
    pac.retransmission = 0;
    pac.flow_metrics.flow_effeciency = 0;
    pac.flow_metrics.flow_load = 0;
    pac.flow_metrics.flow_time = (float)delay/1000000.0f;
    pac.flow_metrics.throughtput = (int)totale_bytes;
    hostent* h = gethostbyaddr((const char*)&ih->daddr, 4, AF_INET);
    pac.host_name = (h != nullptr) ? h->h_name : pac.dst_ip;
    //insert 
    char sql[1024];
    sprintf_s(sql, "INSERT INTO packets (p_size,src_ip,dst_ip,udp_port,bits_per_sec,packet_count,flow_time,throughput,latency,host_name) VALUES (%d,'%s','%s',%d,%.2f,%d,%.2f,%d,%.2f,'%s')",
        pac.p_size, pac.src_ip.c_str(), pac.dst_ip.c_str(), pac.udp_port,
        pac.prot_stats.bits_per_sec, pac.prot_stats.packet_count,
        pac.flow_metrics.flow_time, pac.flow_metrics.throughtput,
        pac.latency, pac.host_name.c_str());
    SQLExecDirectA(hs->stmt, (SQLCHAR*)sql, SQL_NTS);
    //print
    printf("[%s] SIZE=%d SRC=%s:%d DST=%s BPS=%I64u PPS=%I64u LAT=%.2f THROUGHPUT=%d FLOW_TIME=%.2f HOST_NAME:%s\n",
        timestr,
        pac.p_size,
        pac.src_ip.c_str(),
        pac.udp_port,
        pac.dst_ip.c_str(),
        Bps.QuadPart,
        Pps.QuadPart,
        pac.latency,
        pac.flow_metrics.throughtput,
        pac.flow_metrics.flow_time,
        pac.host_name.c_str());

    
    // reset
    totale_bytes = 0;
    totale_packet = 0;


} 
 bool initialiaze_sql_connection(SQLHANDLE& envHandle, SQLHANDLE& connHandle)
 {
     SQLWCHAR   retconstring[SQL_RETURN_CODE_LEN];


     //initializations
     connHandle = NULL;

     //allocation 
     if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &envHandle))
         return false;
     if (SQL_SUCCESS != SQLSetEnvAttr(envHandle, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC2, 0))
         return false;
     if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_DBC, envHandle, &connHandle))
         return false;

     //output
     cout << "Attempting connection to SQL Serveur ...";
     cout << "\n";

     //connect to SQL server

     switch (SQLDriverConnect(connHandle,
         NULL,
         (SQLWCHAR*)L"DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost;DATABASE=telemetry;Trusted_Connection=yes;",
         SQL_NTS,
         (SQLWCHAR*)retconstring,
         1024,
         NULL,
         SQL_DRIVER_NOPROMPT)) {
     case SQL_SUCCESS:
         cout << "successfully connected to SQL server";
         cout << "\n";
         break;
     case SQL_SUCCESS_WITH_INFO:
         cout << "successfully connected to SQL server";
         cout << "\n";
         break;
     case SQL_INVALID_HANDLE:
         cout << "Could not connect to SQL Server";
         cout << "\n";
         return FALSE;
     case SQL_ERROR: {
         SQLWCHAR errMsg[512];
         SQLWCHAR sqlState[6];
         SQLINTEGER nativeErr;
         SQLSMALLINT msgLen;
         SQLGetDiagRec(SQL_HANDLE_DBC, connHandle, 1, sqlState, &nativeErr, errMsg, 512, &msgLen);
         wprintf(L"Error: %s\n", errMsg);
         cout << "Could not connect to SQL Server";
         cout << "\n";
         return false;
     }
     default:
         break;
     }

     //if there is a problem connecting then exit application
     SQLHANDLE testStmt;
     if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_STMT, connHandle, &testStmt))
         return FALSE;

     //output
     cout << "\n";
     cout << "Executing T-SQL query...";
     cout << "\n";

     //if there is a problem executing the query then exit application
     //else display query result
     if (SQL_SUCCESS != SQLExecDirect(testStmt, (SQLWCHAR*)L"SELECT @@VERSION", SQL_NTS)) {
         cout << "Error querying SQL Server";
         cout << "\n";
         return false;
     }
     else {

         //declare output variable and pointer
         SQLCHAR sqlVersion[SQL_RESULT_LEN];
         SQLLEN ptrSqlVersion;;

         while (SQLFetch(testStmt) == SQL_SUCCESS) {

             SQLGetData(testStmt, 1, SQL_C_CHAR, sqlVersion, SQL_RESULT_LEN, &ptrSqlVersion);

             //display query result
             cout << "\nQuery Result:\n\n";
             cout << sqlVersion << endl;
         }
         SQLCloseCursor(testStmt);
         SQLFreeHandle(SQL_HANDLE_STMT,testStmt);
     }
     return true;
 }

int main()
{
    struct timeval st_ts;
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "ip and tcp";
    struct bpf_program fcode;

    //initialize st_ts
    st_ts.tv_sec = 0;
    st_ts.tv_usec = 0;

    
    
    //close connection and free resources
    
    //define handels and variables 
    SQLHANDLE   sqlConnHandle;
    SQLHANDLE   sqlEnvHandle;
    SQLHANDLE   sqlInsertHandle;

    //initialisation

    if (!initialiaze_sql_connection(sqlEnvHandle, sqlConnHandle)) {
        cout << "\nSQL initialization failed. Exiting.\n";
        return -1;
    }

    if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_STMT, sqlConnHandle, &sqlInsertHandle)) {
        cout << "\nFailed to allocate insert statement handle. Exiting.\n";
        return -1;
    }
   

    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }

    /* Retrieve the device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
        NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    inum = 5;

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    if (d == nullptr)
    {
        fprintf(stderr, "\nSelected interface not found.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Open the adapter */
    if (d != NULL) {
        if ((adhandle = pcap_open(d->name, // name of the device
            65536, // portion of the packet to capture. 
            // 65536 grants that the whole packet
            // will be captured on all the MACs.
            PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
            1000, // read timeout
            NULL, // remote authentication
            errbuf // error buffer
        )) == NULL)
        {
            fprintf(stderr,
                "\nUnable to open the adapter. %s is not supported by Npcap\n",
                d->name);
            /* Free the device list */
            pcap_freealldevs(alldevs);
            return -1;
        }
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    cout << "\nlistening on " << (d ? d->description : "unknown") << "...\n";
    if (d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses
         * we suppose to be in a C class network */
        netmask = 0xffffff;


    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    cout << "\nlistening on " << d->description << "...\n";

    /* Put the interface in statstics mode 
    if (pcap_setmode(adhandle, MODE_STAT) < 0)
    {
        fprintf(stderr, "\nError setting the mode.\n");
        pcap_close(adhandle);
        // Free the device list 
        return-1;
    }*/

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    handler_state hs = { st_ts, sqlInsertHandle };
    pcap_loop(adhandle, 0, packet_handler, (u_char*)&hs);
    

    //pause the console window - exit when key is pressed
    cout << "\nPress any key to exit...";
    getchar();

    SQLFreeHandle(SQL_HANDLE_STMT, sqlEnvHandle);
    SQLDisconnect(sqlConnHandle);
    SQLFreeHandle(SQL_HANDLE_DBC, sqlConnHandle);
    SQLFreeHandle(SQL_HANDLE_ENV, sqlInsertHandle);
	return 0;
}