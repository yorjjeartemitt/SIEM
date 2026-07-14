cmake_minimum_required(VERSION 3.16)
project(siem C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

find_library(PCAP_LIB pcap REQUIRED)
find_library(SQLITE3_LIB sqlite3 REQUIRED)

add_executable(siem main.c network/net_capture.c network/net_proto.c network/net_proto_tcp.c network/net_proto_udp.c db.c log.c)

target_include_directories(siem PRIVATE ${CMAKE_SOURCE_DIR}/network ${GTK3_INCLUDE_DIRS})

target_compile_options(siem PRIVATE ${GTK3_CFLAGS_OTHER})

target_link_libraries(siem PRIVATE ${GTK3_LIBRARIES} ${PCAP_LIB} ${SQLITE3_LIB})
add_custom_target(caps COMMAND sudo setcap cap_net_raw,cap_net_admin=eip $<TARGET_FILE:siem> DEPENDS siem COMMENT "Setting cap_net_raw,cap_net_admin on siem binary")