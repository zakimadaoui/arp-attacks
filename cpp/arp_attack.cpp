#include <iostream>
#include <ranges>
#include <PcapLiveDeviceList.h>

int main()
{

    auto devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    for (auto [index, dev] : std::views::enumerate(devList))
    {
        std::cout << index << ": " << dev->getName();
        auto desc = dev->getDesc();
        if (!desc.empty())
        {
            std::cout << ": description: " << desc;
        }
        std::cout << std::endl;
    }

    std::cout << "C++ Implementation coming soon... :)" << std::endl;

    return 0;
}