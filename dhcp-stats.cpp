#include <iostream>
#include <cstring>
#include <vector>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <getopt.h>
using namespace std;


int main (int argc, char *argv[]) {
    char *filename = nullptr;
    char *interface = nullptr;
    vector<string> ip_prefixes;
    int opt;


    // Parse command line arguments
    while ((opt = getopt(argc, argv, "r:i:")) != -1) {
        switch (opt) {
            case 'r':
                filename = optarg;
                break;
            case 'i':
                interface = optarg;
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
    if ((filename == nullptr && interface == nullptr) || (filename != nullptr && interface != nullptr)) {
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
        ip_prefixes.push_back(argv[i]);
    }

    printf("Filename: %s\n", filename);
    printf("Interface: %s\n", interface);
    printf("IP prefixes: ");
    for (int i = 0; i < argc - optind; i++) {
        printf("%s ", ip_prefixes[i].c_str());
    }

    return 0;
}