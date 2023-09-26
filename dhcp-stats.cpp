#include <iostream>
#include <iomanip>
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


using namespace std;

struct prefix_stats {
    string prefix;
    int max_hosts;
    int allocated_addresses;
    double util_percent;
};

struct options {
    char *filename;
    char *interface;
    vector<string> ip_prefixes;
};

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


map<string, prefix_stats> stats_map;

void packet_handler(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {
    // Just check if user and packet_header are not null
    if (user == nullptr || packet_header == nullptr) {
        cout << "";
    }

    // Parse dhcp packet
    struct dhcp_packet *dhcp = (struct dhcp_packet *) 
                                (packet_data + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
    

    // Check if it is DHCPACK packet
    if (dhcp->options[0] == 53 && dhcp->options[2] == 5 && dhcp->op == 2) {
        cout << "DHCPACK packet\n";
        cout << "yiaddr: " << inet_ntoa(*(struct in_addr *)&dhcp->yiaddr) << endl;

    }
}



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

pcap_t *create_pcap_handler(char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer for pcap
    pcap_t *handle = NULL;
    
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;
    
    string filter = "udp and (port 67 or port 68)";

    // Get from interface the netmask and IP address
    if(pcap_lookupnet(interface, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        cerr << "Can't find the device: " << errbuf << endl;
        show_all_interfaces();
        exit(EXIT_FAILURE);
    }

    // Open the device for sniffing
    handle = pcap_open_live(interface, BUFSIZ, false, 1000, errbuf);
    if(handle == NULL) {
        cerr << "Can't open the device: " << errbuf << endl;
        show_all_interfaces();
        exit(EXIT_FAILURE);
    }

    // Compile the filter
    if(pcap_compile(handle, &bpf, filter.c_str(), 0, netmask) == PCAP_ERROR) {
        cerr << "Can't compile the filter: " << pcap_geterr(handle) << endl;
        exit(EXIT_FAILURE);
    }

    // Apply the filter
    if(pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        cerr << "Can't apply the filter: " << pcap_geterr(handle) << endl;
        exit(EXIT_FAILURE);
    }

    return handle;
}

void start_monitor(char *interface, char *filename, vector<string> ip_prefixes) {
    cout << "\n--------------------------------\n";
    cout << "This print is in start_monitor function\n";
    // For debugging purposes
    if (filename != nullptr) {
        printf("Filename: %s\n", filename);
    } else {
        printf("Interface: %s\n", interface);
    }
    printf("IP prefixes: ");
    for (auto &ip_prefix : ip_prefixes) {
        cout << ip_prefix << " ";
    }
    cout << "\n--------------------------------\n";
    //------------------------


    // Create pcap handle
    pcap_t *handle = create_pcap_handler(interface);
    if (handle == NULL) {
        exit(EXIT_FAILURE);
    }

    // Start sniffing
    if (pcap_loop(handle, -1, packet_handler, NULL) == -1){
        cerr << "Error in pcap_loop: " << pcap_geterr(handle) << endl;
        exit(EXIT_FAILURE);
    }

    pcap_close(handle);
}

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
                cerr << "Usage: ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n";
                cerr << "\n-r <filename> - statistika bude vytvořena z pcap souborů";
                cerr << "\n-i <interface> - rozhraní, na kterém může program naslouchat";
                cerr << "\n<ip-prefix> - rozsah sítě pro které se bude generovat statistika\n";
                cerr << "\nNapř.\n ./dhcp-stats -i eth0 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24";
                exit(EXIT_FAILURE);
        }
    }

    // If filename and interface are not specified, exit
    if ((opts.filename == nullptr && opts.interface == nullptr) || (opts.filename != nullptr && opts.interface != nullptr)) {
        cerr << "Expected either filename or interface\n";
        cerr << "Or you entered both of them\n";
        exit(EXIT_FAILURE);
    }

    // Check if there are any prefixes
    if (optind >= argc ) {
        cerr << "Expected at least one IP prefix\n";
        exit(EXIT_FAILURE);
    }

    for (int i = optind; i < argc; i++) {
        opts.ip_prefixes.push_back(argv[i]);
    }


    return opts;
}

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
        ps.max_hosts = pow(2, 32 - stoi(ip_prefix.substr(ip_prefix.find('/') + 1))) - 2;
        ps.allocated_addresses = 0;
        ps.util_percent = 0.0;
        stats_map[ip_prefix] = ps;
    }

    /*
    if (opts.filename != nullptr) {
        cout << "Interface didn't found, then it's Filename: " << opts.filename << endl;
    } else {
        cout << "Filename didn't found, then it's Interface: " << opts.interface << endl;
    }

    // Show prefix stats map
    cout << "IP-Prefix Max-hosts Allocated addresses Utilization" << endl;
    for (auto &prefix : stats_map) {
        cout << prefix.first << " " << prefix.second.max_hosts << " " << prefix.second.allocated_addresses << " " << prefix.second.util_percent << endl;
    }
    exit(EXIT_SUCCESS);
    */  


    // Create pcap handle
    start_monitor(opts.interface, opts.filename, opts.ip_prefixes);
    return 0;
}