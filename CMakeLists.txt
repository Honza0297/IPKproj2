cmake_minimum_required(VERSION 3.13)
project(IPKproj2 C)

set(CMAKE_C_STANDARD 99)
SET(GCC_COVERAGE_LINK_FLAGS    "-libpcap")

include(FindPCAP.cmake)

add_executable(IPKproj2 main.c Linear_lists.h Linear_lists.c)
target_link_libraries(IPKproj2 ${PCAP_LIBRARY})
