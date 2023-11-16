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
 * @brief structure for storing statistics about prefixes
*/
struct prefix_stats {
    string prefix;
    int max_hosts;
    int allocated_addresses;
    double util_percent;
    bool is_logged;
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
    uint8_t options[]; 
};


map<string, prefix_stats> stats_map; //  map for storing statistics about prefixes
pcap_t *handle; // pcap handler
bool in_offline = false; // If we are in offline mode
vector<uint32_t> allocated_addresses; // Vector for storing allocated addresses


/**
 * @brief Function that checks if yiaddr is already in allocated_addresses or not
 * @return void
*/

bool is_in_allocated_addresses(uint32_t yiaddr) {
    bool found = false;

    for(auto &addr : allocated_addresses) {
        if (addr == yiaddr) {
            found = true;
            break;
        }
    }

    if (!found) {
        // Add yiaddr to allocated addresses
        allocated_addresses.push_back(yiaddr);
        return true;
    }
    else {
        return false;
    }
}


/**
 * @brief Checks, if yiaddrs is in one of the prefixes
 * @param uint32_t yiaddr
 * @return bool
*/
bool is_in_prefixes(uint32_t yiaddr) {
    // One IP address can be in multiple prefixes, so I used a bool variable
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

        // Check if allocated addresses is more than max hosts
        if(prefix.second.allocated_addresses >= prefix.second.max_hosts) {
            // Stop counting allocated addresses
            continue;
        }
        else {
            // Check if yiaddr is in prefix
            if ((yiaddr_byte & mask_byte) == prefix_byte) {
                // Check if yiaddr is not network or broadcast address
                if (yiaddr_byte == prefix_byte || yiaddr_byte == (prefix_byte | ~mask_byte)) {
                    continue;
                }
                prefix.second.allocated_addresses++;   
                is_in_prefix = true;        
            }
        }
    }

    return is_in_prefix;
}

/**
 * @brief function prints monitor traffic stats
 * @return void
*/
void print_traffic_online() {

    // Ncurses settings
    initscr();
    cbreak(); 
    noecho();
    curs_set(false);
    WINDOW *win = newwin(10, 70, 0, 0);
    refresh();
    scrollok(win, true);

     // Show prefix stats map
    wprintw(win, "IP-Prefix Max-hosts Allocated addresses Utilization\n");
    wrefresh(win);
    int row = 1;
    for (auto &prefix : stats_map) {
        // Calculate utilization
        prefix.second.util_percent = (double)prefix.second.allocated_addresses / (double)prefix.second.max_hosts * 100;
        
        // If util percent is more thatn 50%, log it
        if((prefix.second.util_percent >= 50) && (!prefix.second.is_logged)) {
            prefix.second.is_logged = true;
            // Log it
            setlogmask(LOG_UPTO(LOG_NOTICE));
            openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
            syslog(LOG_NOTICE, "Prefix %s exceeded 50%% of allocations.", prefix.second.prefix.c_str());
            closelog();
        } 

        // Print it
        mvwprintw(win, row, 0, "%s %d %d %.2f%%\n", prefix.second.prefix.c_str(), prefix.second.max_hosts, prefix.second.allocated_addresses, prefix.second.util_percent);
        row++;

        // refresh windows
        wrefresh(win);
    }

    row += 2; // for more space to make it readable
    // Print if utilization is more than 50% in window
    for (auto &prefix : stats_map) {
        if (prefix.second.util_percent >= 50) {
            mvwprintw(win, row, 0, "Prefix %s exceeded 50%% of allocations.", prefix.second.prefix.c_str());
            row++;
            // refresh windows
            wrefresh(win);
        }
    }

    // Wait 150ms
    napms(150);
}

/**
 * @brief Function that prints traffic stats from pcap file
 * @return void
*/
void print_traffic_offline() {
    // Show prefix stats map
    cout << "IP-Prefix Max-hosts Allocated addresses Utilization" << endl;

    // Print stats
    for (auto &prefix : stats_map) {
        printf("%s %d %d %.2f%%\n", prefix.second.prefix.c_str(), prefix.second.max_hosts, prefix.second.allocated_addresses, prefix.second.util_percent);
    }

    printf("\n");
    // Now print if utilization is more than 50%
    for (auto &prefix : stats_map) {
        if (prefix.second.util_percent >= 50) {
            printf("Prefix %s exceeded 50%% of allocations.\n", prefix.second.prefix.c_str());
        }
    }
}



/**
 * @brief Function for handling packets from pcap_loop
 * @param u_char *user
 * @param const struct pcap_pkthdr *packet_header
 * @param const u_char *packet_data
*/
void packet_handler(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {
    // Just check if user and packet_header are not null, so -Wall and -Wextra will not say anything while compiling
    if (user == nullptr || packet_header == nullptr) {
        cout << "";
    }

    struct dhcp_packet *dhcp = (struct dhcp_packet *)(packet_data + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    

    uint8_t *options = dhcp->options;
    // Source: https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
    // DHCP options field does not have to be sorted, e.g option 53 goes firtst and then others, they can be in any order
    while(*options != 0xFF){ // 255 is max value of options
        uint8_t option_code = *options;
        uint8_t option_len = *(options + 1);

        // Check if it is DHCPACK packet 
        // 53 => that it is DHCP message type
        // 1 => that it is 1 byte long
        if (option_code == 53 && option_len == 1) {
            uint8_t message_type = *(options + 2);

            // 5 => that Messeage type DHCPACK
            // 2 => that it is reply packet
            if (message_type == 5 && dhcp->op == 2) {
                // Check if yiaddr is in one of the prefixes
                if (is_in_allocated_addresses(dhcp->yiaddr)) {
                    // Check if yiaddr is already in allocated_addresses
                    if (is_in_prefixes(dhcp->yiaddr)) { 
                        // Check if we need to print with ncurse or stdout
                        if (in_offline) {
                            // Just calculate
                            for (auto &prefix : stats_map) {
                                // Calculate utilization
                                prefix.second.util_percent = (double)prefix.second.allocated_addresses / (double)prefix.second.max_hosts * 100;
                                // If util percent is more thatn 50%, log it
                                if(prefix.second.util_percent >= 50 && !prefix.second.is_logged) {
                                    setlogmask(LOG_UPTO(LOG_NOTICE));
                                    openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
                                    syslog(LOG_NOTICE, "Prefix %s exceeded 50%% of allocations.", prefix.second.prefix.c_str());
                                    prefix.second.is_logged = true;
                                    closelog();
                                } 
                            }
                        }
                        else {
                            print_traffic_online();
                        }
                    } 
                }
            }
        }
        // Go to next option
        options += option_len + 2;
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
pcap_t *create_pcap_handler(char *interface, char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer for pcap
    pcap_t *handle = NULL;
    
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;
    
    string filter = "udp and (port 67)";

    if (filename != nullptr) { // Configure for pcap file
        handle = pcap_open_offline(filename, errbuf);
         // For pcap files we dont need to get netmask and srcip
        if(pcap_compile(handle, &bpf, filter.c_str(), 0, 0) == PCAP_ERROR) {
            cerr << "ERROR: Can't compile the filter: " << pcap_geterr(handle) << endl;
            exit(EXIT_FAILURE);
        }
        // Turn on offline mode
        in_offline = true;
    }
    else { // Configure for interface
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
        pcap_close(handle);
        exit(EXIT_SUCCESS);
    }
    else if (in_offline) {
        print_traffic_offline();;
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

    handle = create_pcap_handler(interface, filename);
    if (handle == NULL) {
        cerr << "ERROR: Can't create pcap handler\n";
        exit(EXIT_FAILURE);
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
        ps.is_logged = false;
        stats_map[ip_prefix] = ps;
    }

    // Start sniffing
    start_monitor(opts.interface, opts.filename);
    return 0;
}