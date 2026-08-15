#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdint>
#include <csignal>
#include <ctime>
#include <map>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>


static volatile std::sig_atomic_t g_running = 1;

void signalHandler(int signum)
{
    (void)signum;
    g_running = 0;
}


struct CaptureStats
{
    uint64_t totalPackets   = 0;
    uint64_t totalBytes     = 0;
    std::map<uint8_t, uint64_t> countByType; 

    void record(uint8_t type, size_t size)
    {
        totalPackets++;
        totalBytes += size;
        countByType[type]++;
    }

    void print() const
    {
        std::cout << "\n=========================== CAPTURE SUMMARY ===========================\n";
        std::cout << "Total packets captured : " << totalPackets << "\n";
        std::cout << "Total bytes captured   : " << totalBytes   << "\n";
        std::cout << "-------------------------------------------------------------------------\n";
        for (const auto& [type, count] : countByType)
        {
            std::cout << "  ICMP type " << std::setw(3) << (int)type
                      << " (" << icmpTypeName(type) << ") : " << count << " packet(s)\n";
        }
        std::cout << "=========================================================================\n";
    }

    static std::string icmpTypeName(uint8_t type)
    {
        switch (type)
        {
            case ICMP_ECHOREPLY:      return "Echo Reply";
            case ICMP_DEST_UNREACH:   return "Destination Unreachable";
            case ICMP_SOURCE_QUENCH:  return "Source Quench";
            case ICMP_REDIRECT:       return "Redirect";
            case ICMP_ECHO:           return "Echo Request";
            case ICMP_TIME_EXCEEDED:  return "Time Exceeded";
            case ICMP_PARAMETERPROB:  return "Parameter Problem";
            case ICMP_TIMESTAMP:      return "Timestamp Request";
            case ICMP_TIMESTAMPREPLY: return "Timestamp Reply";
            case ICMP_INFO_REQUEST:   return "Information Request";
            case ICMP_INFO_REPLY:     return "Information Reply";
            case ICMP_ADDRESS:        return "Address Mask Request";
            case ICMP_ADDRESSREPLY:   return "Address Mask Reply";
            default:                  return "Unknown";
        }
    }

    static std::string destUnreachCodeName(uint8_t code)
    {
        switch (code)
        {
            case ICMP_NET_UNREACH:    return "Network Unreachable";
            case ICMP_HOST_UNREACH:   return "Host Unreachable";
            case ICMP_PROT_UNREACH:   return "Protocol Unreachable";
            case ICMP_PORT_UNREACH:   return "Port Unreachable";
            case ICMP_FRAG_NEEDED:    return "Fragmentation Needed / DF set";
            case ICMP_SR_FAILED:      return "Source Route Failed";
            default:                  return "Other";
        }
    }
};


uint16_t computeChecksum(const uint8_t* data, size_t length)
{
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);

    while (length > 1)
    {
        sum += *ptr++;
        length -= 2;
    }

    if (length == 1)
    {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}


std::string currentTimestamp()
{
    struct timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tmVal{};
    localtime_r(&ts.tv_sec, &tmVal);

    char buf[32];
    strftime(buf, sizeof(buf), "%H:%M:%S", &tmVal);

    std::ostringstream oss;
    oss << buf << "." << std::setw(3) << std::setfill('0') << (ts.tv_nsec / 1000000);
    return oss.str();
}


class ICMPSniffer
{
public:
    ICMPSniffer(std::string listenAddr, std::string filterIP)
        : listenAddr_(std::move(listenAddr)),
          filterIP_(std::move(filterIP)),
          sockfd_(-1)
    {
    }

    ~ICMPSniffer()
    {
        if (sockfd_ >= 0)
        {
            close(sockfd_);
        }
    }

    bool open()
    {
        sockfd_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd_ < 0)
        {
            std::cerr << "[ERROR] Failed to create raw socket: "
                      << strerror(errno) << "\n";
            std::cerr << "[HINT]  Raw sockets require root privileges. "
                         "Try running with 'sudo'.\n";
            return false;
        }

        struct sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = inet_addr(listenAddr_.c_str());

        if (bind(sockfd_, reinterpret_cast<struct sockaddr*>(&bindAddr),
                 sizeof(bindAddr)) < 0)
        {
            std::cerr << "[ERROR] Failed to bind socket: "
                      << strerror(errno) << "\n";
            return false;
        }

        struct timeval tv{};
        tv.tv_sec  = 1;
        tv.tv_usec = 0;
        setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        return true;
    }

    void run()
    {
        std::vector<uint8_t> buffer(65535);

        std::cout << "[INFO] Capture started. Press Ctrl+C to stop.\n\n";

        while (g_running)
        {
            struct sockaddr_in peer{};
            socklen_t peerLen = sizeof(peer);

            ssize_t received = recvfrom(
                sockfd_,
                buffer.data(),
                buffer.size(),
                0,
                reinterpret_cast<struct sockaddr*>(&peer),
                &peerLen
            );

            if (received < 0)
            {
                

                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    continue;
                }
                std::cerr << "[ERROR] recvfrom() failed: " << strerror(errno) << "\n";
                continue;
            }

            processPacket(buffer.data(), static_cast<size_t>(received), peer);
        }

        stats_.print();
    }

private:
    void processPacket(const uint8_t* buffer, size_t length,
                        const struct sockaddr_in& peer)
    {
        if (length < sizeof(struct ip))
        {
            std::cerr << "[WARN] Packet too small to contain an IP header, dropped.\n";
            return;
        }

        const struct ip* ipHeader = reinterpret_cast<const struct ip*>(buffer);
        int ipHeaderLen = ipHeader->ip_hl * 4; // ip_hl is in 32-bit words

        if (length < static_cast<size_t>(ipHeaderLen) + sizeof(struct icmphdr))
        {
            std::cerr << "[WARN] Packet too small to contain a valid ICMP header, dropped.\n";
            return;
        }

        char srcIPStr[INET_ADDRSTRLEN];
        char dstIPStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIPStr, sizeof(srcIPStr));
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIPStr, sizeof(dstIPStr));

        std::string srcIP(srcIPStr);
        std::string dstIP(dstIPStr);

       
        if (!filterIP_.empty() && srcIP != filterIP_ && dstIP != filterIP_)
        {
            return;
        }

        const struct icmphdr* icmpHeader =
            reinterpret_cast<const struct icmphdr*>(buffer + ipHeaderLen);

        size_t icmpLength = length - ipHeaderLen;

        // Verify checksum for data integrity reporting.
        uint16_t receivedChecksum = icmpHeader->checksum;
        std::vector<uint8_t> icmpCopy(buffer + ipHeaderLen, buffer + length);
        reinterpret_cast<struct icmphdr*>(icmpCopy.data())->checksum = 0;
        uint16_t calculatedChecksum = computeChecksum(icmpCopy.data(), icmpLength);
        bool checksumValid = (receivedChecksum == calculatedChecksum);

        stats_.record(icmpHeader->type, length);

        printPacketDetails(srcIP, dstIP, ipHeader, icmpHeader, icmpLength, checksumValid);
    }

    // Prints a detailed, formatted breakdown of one captured ICMP packet.
    void printPacketDetails(const std::string& srcIP, const std::string& dstIP,
                             const struct ip* ipHeader,
                             const struct icmphdr* icmpHeader,
                             size_t icmpLength, bool checksumValid)
    {
        std::cout << "-------------------------------------------------------------------------\n";
        std::cout << "[" << currentTimestamp() << "] ICMP Packet Captured\n";
        std::cout << "  Source IP        : " << srcIP << "\n";
        std::cout << "  Destination IP   : " << dstIP << "\n";
        std::cout << "  IP TTL           : " << (int)ipHeader->ip_ttl << "\n";
        std::cout << "  IP Total Length  : " << ntohs(ipHeader->ip_len) << " bytes\n";
        std::cout << "  ICMP Type        : " << (int)icmpHeader->type
                   << " (" << CaptureStats::icmpTypeName(icmpHeader->type) << ")\n";
        std::cout << "  ICMP Code        : " << (int)icmpHeader->code << "\n";
        std::cout << "  ICMP Length      : " << icmpLength << " bytes\n";
        std::cout << "  Checksum Valid   : " << (checksumValid ? "yes" : "NO (corrupted?)") << "\n";

        switch (icmpHeader->type)
        {
            case ICMP_ECHO:
            case ICMP_ECHOREPLY:
                std::cout << "  Echo Identifier  : " << ntohs(icmpHeader->un.echo.id) << "\n";
                std::cout << "  Echo Sequence    : " << ntohs(icmpHeader->un.echo.sequence) << "\n";
                break;

            case ICMP_DEST_UNREACH:
                std::cout << "  Unreachable Type : "
                           << CaptureStats::destUnreachCodeName(icmpHeader->code) << "\n";
                break;

            case ICMP_TIME_EXCEEDED:
                std::cout << "  Reason           : "
                           << (icmpHeader->code == ICMP_EXC_TTL
                                   ? "TTL expired in transit"
                                   : "Fragment reassembly time exceeded") << "\n";
                break;

            case ICMP_REDIRECT:
                std::cout << "  Note             : Router requests route change (Redirect)\n";
                break;

            default:
               
                break;
        }

        std::cout << "-------------------------------------------------------------------------\n\n";
    }

    std::string listenAddr_;
    std::string filterIP_;
    int sockfd_;
    CaptureStats stats_;
};


void printBanner(const std::string& listenAddr, const std::string& filterIP)
{
    std::cout <<
        "===========================================================\n"
        "                 ICMP PACKET SNIFFER (C++)                 \n"
        "===========================================================\n";

    std::cout << "| " << std::left << std::setw(20) << "Listening Interface"
               << " | " << std::setw(30) << listenAddr << " |\n";
    std::cout << "| " << std::left << std::setw(20) << "Target Filter"
               << " | " << std::setw(30) << (filterIP.empty() ? "ANY" : filterIP) << " |\n";
    std::cout << "| " << std::left << std::setw(20) << "Protocol"
               << " | " << std::setw(30) << "ICMPv4" << " |\n";
    std::cout << "===========================================================\n\n";
}


int main(int argc, char* argv[])
{
    std::string listenAddr = "0.0.0.0";
    std::string filterIP   = (argc > 1) ? argv[1] : "";

    
    std::signal(SIGINT, signalHandler);

    printBanner(listenAddr, filterIP);

    ICMPSniffer sniffer(listenAddr, filterIP);

    if (!sniffer.open())
    {
        return EXIT_FAILURE;
    }

    sniffer.run();

    std::cout << "[INFO] Capture stopped. Goodbye.\n";
    return EXIT_SUCCESS;
}
