cmake_minimum_required(VERSION 3.20)

# use vcpkg for package management
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

project(ArpAttack
    VERSION 1.0
    DESCRIPTION "C++ App that performs some common ARP attacks"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # avoid compiler-specific flavors


# dependencies
# find_package(fmt CONFIG REQUIRED)
find_package(PcapPlusPlus CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS 
    asio
)

add_executable(arp_attack arp_attack.cpp)
target_link_libraries(arp_attack PRIVATE 
    PcapPlusPlus::Pcap++ 
    PcapPlusPlus::Packet++ 
    PcapPlusPlus::Common++
    Boost::asio
)

target_compile_options(arp_attack PRIVATE 
    -Wall 
    -Wextra 
    -Wpedantic 
    -Werror
    -Wnon-virtual-dtor
)

target_include_directories(arp_attack PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

