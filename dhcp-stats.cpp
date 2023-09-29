/**
 * @file dhcp-stats.cpp
 * @author Assatulla Dias 3BIT VUT FIT
*/
#include <iostream>
#include <iomanip>
#include <csignal>
#include <math.h>
#include <cstring>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <map>
#include <syslog.h>
#include <ncurses.h>


using namespace std;

/**
 * 
 * TODO: Need to add syslog -> Done // Check in VM ubuntu
 * TODO: Need to add function, so it works with file pcap
 * TODO: Beatiful output of log stats using ncurses
*/

/**
 * @brief structure for storing statistics about prefixes
*/
struct prefix_stats {
    string prefix;
    int max_hosts;
    int allocated_addresses;
    double util_percent;
};

/**
 * @brief structure for storing command line arguments
*/
struct options {
    char *filename;
    char *interface;
    vector<string> ip_prefixes;
};

/**
 * @brief structure of dhcp packet, so I can work with that packet easier
*/
struct dhcp_packet {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t magic_cookie;
    uint8_t options[0];
};

/**
 * @brief map for storing statistics about prefixes
*/
map<string, prefix_stats> stats_map;
pcap_t *handle;

/**
 * @brief Checks, if yiaddrs is in one of the prefixes
 * @param uint32_t yiaddr
 * @return bool
*/
bool is_in_prefixes(uint32_t yiaddr) {
    bool is_in_prefix = false;
    for (auto &prefix : stats_map) {
        // Get prefix and mask
        string prefix_str = prefix.first.substr(0, prefix.first.find('/'));
        int mask = stoi(prefix.first.substr(prefix.first.find('/') + 1));

        // Get prefix and mask in network byte order
        uint32_t prefix_byte = ntohl(inet_addr(prefix_str.c_str()));
        uint32_t mask_byte = 0xFFFFFFFF << (32 - mask);

        // Get yiaddr in network byte order
        uint32_t yiaddr_byte = ntohl(yiaddr);

        // Check if yiaddr is in prefix
        if ((yiaddr_byte & mask_byte) == prefix_byte) {
            // Add this yiaddr to allocated addresses
            prefix.second.allocated_addresses++;
            is_in_prefix = true;
        }
    }
    return is_in_prefix;
}

/**
 * @brief function prints monitor traffic stats
 * @return void
*/
void print_traffic() {
    initscr();
    cbreak();
    noecho();
    curs_set(false);

    WINDOW *win = newwin(10, 40, 0, 0);
    refresh();
        
    // syslog init
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    scrollok(win, true);

     // Show prefix stats map
    wprintw(win, "IP-Prefix Max-hosts Allocated addresses Utilization\n");
    wrefresh(win);
    int i = 0;
    for (auto &prefix : stats_map) {
        
        wmove(win, i = 1, 0);
        wclrtoeol(win);
        
        // Calculate utilization
        prefix.second.util_percent = (double)prefix.second.allocated_addresses / (double)prefix.second.max_hosts * 100;
        // If util percent is more thatn 50%, log it
        if(prefix.second.util_percent >= 50) {
            // Log it
            syslog(LOG_INFO, "Prefix %s exceeded 50%% of allocations.", prefix.second.prefix.c_str());
        } 


        wprintw(win, "%s %d %d ", prefix.second.prefix.c_str(), prefix.second.max_hosts, prefix.second.allocated_addresses);
        if (prefix.second.util_percent < 10) {
            wprintw(win, "0%.2f%%\n", prefix.second.util_percent);
        }
        else {
            wprintw(win, "%.2f%%\n", prefix.second.util_percent);
        }

        wrefresh(win);
       

        i++;
    }

    napms(300);
}

/**
 * @brief Function for handling packets from pcap_loop
 * @param u_char *user
 * @param const struct pcap_pkthdr *packet_header
 * @param const u_char *packet_data
*/
void packet_handler(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {
    // Just check if user and packet_header are not null
    if (user == nullptr || packet_header == nullptr) {
        cout << "";
    }

    // Parse dhcp packet
    struct dhcp_packet *dhcp = (struct dhcp_packet *)(packet_data + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    

    // Check if it is DHCPACK packet
    if (dhcp->options[0] == 53 && dhcp->options[2] == 5 && dhcp->op == 2) {
        // Check if yiaddr is in one of the prefixes
        if (is_in_prefixes(dhcp->yiaddr)) {
            print_traffic();
        }
    }
}


/**
 * @brief Function for showing all interfaces, if user enters wrong interface or no interface
*/
void show_all_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_if_t *alldevs;
    pcap_if_t *d;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error in pcap_findalldevs: " << errbuf << endl;
         exit(1);
    }

    for(d = alldevs; d != nullptr; d = d->next) {
        cout << d->name << endl;
    }

    printf("\n");
    pcap_freealldevs(alldevs);
}

/**
 * @brief Function for creating pcap handler
 * @param char *interface
 * @return pcap_t *
*/
pcap_t *create_pcap_handler(char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer for pcap
    pcap_t *handle = NULL;
    
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;
    
    string filter = "udp and (port 67)";

    // Get from interface the netmask and IP address
    if(pcap_lookupnet(interface, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        cerr << "ERROR: Can't find the device: " << errbuf << endl;
        show_all_interfaces();
        exit(EXIT_FAILURE);
    }

    // Open the device for sniffing
    handle = pcap_open_live(interface, BUFSIZ, false, 1000, errbuf);
    if(handle == NULL) {
        cerr << "ERROR: Can't open the device: " << errbuf << endl;
        show_all_interfaces();
        exit(EXIT_FAILURE);
    }

    // Compile the filter
    if(pcap_compile(handle, &bpf, filter.c_str(), 0, netmask) == PCAP_ERROR) {
        cerr << "ERROR: Can't compile the filter: " << pcap_geterr(handle) << endl;
        exit(EXIT_FAILURE);
    }

    // Apply the filter
    if(pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        cerr << "ERROR: Can't apply the filter: " << pcap_geterr(handle) << endl;
        exit(EXIT_FAILURE);
    }

    return handle;
}

/**
 * @brief Stops to reading packets and closes the pcap handler.
 * 
 * @param signals
*/
void stop_sniffer(int signal)
{ 
    if (signal == SIGINT || signal == SIGTERM || signal == SIGQUIT) {
        endwin();
        closelog();
        pcap_close(handle);
        exit(EXIT_SUCCESS);
    }
}

/** May be need to change later
 * @brief Function for starting sniffing DHCP packets
 * @param char *interface
 * @param char *filename
 * @param vector<string> ip_prefixes
*/
void start_monitor(char *interface, char *filename) {
    // Signal handler
    signal(SIGINT, stop_sniffer);
    signal(SIGTERM, stop_sniffer);
    signal(SIGQUIT, stop_sniffer);

    // check if program runs with file or interface
    if (filename != nullptr) {
        cout << "Progam did not implemented yet for pcap files\n";
        exit(EXIT_SUCCESS);
    }
    else {
        // Create pcap handle
        handle = create_pcap_handler(interface);
        if (handle == NULL) {
            exit(EXIT_FAILURE);
        }
    }
    

    // Start sniffing
    if (pcap_loop(handle, -1, packet_handler, NULL) == -1){
        cerr << "ERROR: pcap_loop: " << pcap_geterr(handle) << endl;
        exit(EXIT_FAILURE);
    }

    // Close the pcap handler    
    stop_sniffer(0);
    return;
}


/**
 * @brief function, that checks, if prefix is valid
 * @param string ip_prefix
 * @return bool
*/

void check_prefix(string ip_prefix) {
    size_t slash_pos = ip_prefix.find('/');
    if(slash_pos == string::npos) {
        cout << "ERROR: IP prefix is not valid! Didn't found '/' " << ip_prefix << "\n";
        exit(EXIT_FAILURE);
    }

    string ip_str = ip_prefix.substr(0, slash_pos);
    string mask_str = ip_prefix.substr(slash_pos + 1);

    //cout << "ip_str: " << ip_str << endl;
    //cout << "mask_str: " << mask_str << endl;
    
    // Check if ip is valid
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_str.c_str(), &(sa.sin_addr));
    if (result != 1) { // IP is not valid
        cout << "ERROR: IP is not valid " << ip_str << "\n";
        exit(EXIT_FAILURE);
    }
    
    // Check if the mask is valid
    int mask = stoi(mask_str);
    if (mask < 0 || mask > 32) {
        cout << "ERROR: IP mask is not valid " << mask << "\n";
        exit(EXIT_FAILURE);
    }

}

/**
 * @brief Function for parsing command line arguments
 * @param int argc
 * @param char *argv[]
 * @param options opts
 * @return options
*/
options parse_args(int argc, char *argv[], options opts) {

    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "r:i:")) != -1) {
        switch (opt) {
            case 'r':
                opts.filename = optarg;
                break;
            case 'i':
                opts.interface = optarg;
                break;
            default:
                cerr << "ERROR: Unknown argument\n\n";
                cerr << "--------------------------------\n";
                cerr << "Usage: ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n";
                cerr << "\n-r <filename> - statistika bude vytvořena z pcap souborů";
                cerr << "\n-i <interface> - rozhraní, na kterém může program naslouchat";
                cerr << "\n<ip-prefix> - rozsah sítě pro které se bude generovat statistika\n";
                cerr << "\nNapř.\n ./dhcp-stats -i eth0 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24";
                cerr << "\n--------------------------------\n";
                exit(EXIT_FAILURE);
        }
    }

    // If filename and interface are not specified, exit
    if ((opts.filename == nullptr && opts.interface == nullptr) || (opts.filename != nullptr && opts.interface != nullptr)) {
        cerr << "ERROR: Expected either filename or interface\n";
        cerr << "Or you entered both of them\n";
        exit(EXIT_FAILURE);
    }

    // Check if there are any prefixes
    if (optind >= argc ) {
        cerr << "ERROR: Expected at least one IP prefix\n";
        exit(EXIT_FAILURE);
    }

    for (int i = optind; i < argc; i++) {
        // Check if prefix is valid
        check_prefix(argv[i]);
        opts.ip_prefixes.push_back(argv[i]);
    }


    return opts;
}
/**
 * @brief Main function
*/
int main (int argc, char *argv[]) {
    options opts;
    opts.filename = nullptr;
    opts.interface = nullptr;


    // Parse command line arguments
    opts = parse_args(argc, argv, opts);

    // Initialize prefix stats map
    for (auto &ip_prefix : opts.ip_prefixes) {
        prefix_stats ps;
        ps.prefix = ip_prefix;
        ps.max_hosts = pow(2, 32 - stoi(ip_prefix.substr(ip_prefix.find('/') + 1))) - 2; // -2 because of network and broadcast address
        ps.allocated_addresses = 0;
        ps.util_percent = 0.0;
        stats_map[ip_prefix] = ps;
    }

    // Start sniffing
    start_monitor(opts.interface, opts.filename);
    return 0;
}