#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>

class ICMPListener {
public:
    ICMPListener(const std::string& listenAddr, const std::string& filter)
        : listenAddr_(listenAddr), filter_(filter), sockfd_(-1) {}

    ~ICMPListener() {
        if (sockfd_ >= 0) {
            close(sockfd_);
        }
    }

    bool open() {
        sockfd_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd_ < 0) {
            std::cerr << "Failed to open raw socket: " << strerror(errno) << std::endl;
            std::cerr << "Note: this program requires root privileges." << std::endl;
            return false;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(listenAddr_.c_str());

        if (bind(sockfd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Bind failed: " << strerror(errno) << std::endl;
            return false;
        }

        return true;
    }

    void start() {
        uint8_t buffer[65535];

        while (true) {
            struct sockaddr_in peer{};
            socklen_t peerLen = sizeof(peer);

            ssize_t n = recvfrom(sockfd_, buffer, sizeof(buffer), 0,
                                  (struct sockaddr*)&peer, &peerLen);
            if (n < 0) {
                std::cerr << "recvfrom error: " << strerror(errno) << std::endl;
                continue;
            }

            std::string srcIP = inet_ntoa(peer.sin_addr);

            if (!filter_.empty() && srcIP != filter_) {
                continue;
            }

            handlePacket(srcIP, buffer, n);
        }
    }

private:
    void handlePacket(const std::string& srcIP, const uint8_t* buffer, ssize_t size) {
        // Skip the IP header to get to the ICMP header
        struct ip* ipHdr = (struct ip*)buffer;
        int ipHeaderLen = ipHdr->ip_hl * 4;

        if (size < ipHeaderLen + (int)sizeof(struct icmphdr)) {
            return; // packet too small to contain a valid ICMP header
        }

        struct icmphdr* icmpHdr = (struct icmphdr*)(buffer + ipHeaderLen);

        char timeStr[16];
        time_t now = time(nullptr);
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", localtime(&now));

        switch (icmpHdr->type) {
            case ICMP_ECHO:
                printf("[%s] Echo Request  from %-15s | id=%d seq=%d size=%zdB\n",
                       timeStr, srcIP.c_str(),
                       ntohs(icmpHdr->un.echo.id),
                       ntohs(icmpHdr->un.echo.sequence),
                       size);
                break;

            case ICMP_ECHOREPLY:
                printf("[%s] Echo Reply    from %-15s | id=%d seq=%d size=%zdB\n",
                       timeStr, srcIP.c_str(),
                       ntohs(icmpHdr->un.echo.id),
                       ntohs(icmpHdr->un.echo.sequence),
                       size);
                break;

            case ICMP_DEST_UNREACH:
                printf("[%s] Destination Unreachable from %-15s | size=%zdB\n",
                       timeStr, srcIP.c_str(), size);
                break;

            case ICMP_TIME_EXCEEDED:
                printf("[%s] Time Exceeded from %-15s | size=%zdB\n",
                       timeStr, srcIP.c_str(), size);
                break;

            default:
                printf("[%s] ICMP Type=%d from %-15s | size=%zdB\n",
                       timeStr, icmpHdr->type, srcIP.c_str(), size);
                break;
        }
    }

    std::string listenAddr_;
    std::string filter_;
    int sockfd_;
};

int main(int argc, char* argv[]) {
    std::string listenAddr = "0.0.0.0";
    std::string targetFilter = (argc > 1) ? argv[1] : "";

    std::cout << "---------------------------------------------------------\n";
    printf("| %-20s | %-25s |\n", "Listening Interface", listenAddr.c_str());
    printf("| %-20s | %-25s |\n", "Target Filter",
           targetFilter.empty() ? "ANY" : targetFilter.c_str());
    std::cout << "---------------------------------------------------------\n";

    ICMPListener listener(listenAddr, targetFilter);
    if (!listener.open()) {
        return 1;
    }

    listener.start();
    return 0;
}
