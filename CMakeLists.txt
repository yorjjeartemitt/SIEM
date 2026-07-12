cmake_minimum_required(VERSION 3.10)
project(siem C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

add_executable(siem main.c log.c db.c)

target_include_directories(siem PRIVATE ${GTK3_INCLUDE_DIRS} ${SQLITE3_INCLUDE_DIRS})
target_compile_options(siem PRIVATE ${GTK3_CFLAGS_OTHER} ${SQLITE3_CFLAGS_OTHER} -Wall)
target_link_libraries(siem ${GTK3_LIBRARIES} ${SQLITE3_LIBRARIES})