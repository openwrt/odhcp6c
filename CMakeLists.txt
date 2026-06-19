cmake_minimum_required(VERSION 3.13)
cmake_policy(SET CMP0015 NEW)


# Project Definition
project(odhcp6c LANGUAGES C)
add_executable(${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE
	src/config.c
	src/dhcpv6.c
	src/odhcp6c.c
	src/ra.c
	src/script.c
)


# Compiler Options
set_target_properties(${PROJECT_NAME} PROPERTIES C_STANDARD 11)
target_compile_definitions(${PROJECT_NAME} PRIVATE _GNU_SOURCE)
target_compile_options(${PROJECT_NAME} PRIVATE -g3)
target_compile_options(${PROJECT_NAME} PRIVATE -Os)
target_compile_options(${PROJECT_NAME} PRIVATE -Wall)
target_compile_options(${PROJECT_NAME} PRIVATE -Werror)
target_compile_options(${PROJECT_NAME} PRIVATE -Wextra)
target_compile_options(${PROJECT_NAME} PRIVATE -Werror=implicit-function-declaration)
target_compile_options(${PROJECT_NAME} PRIVATE -Wformat)
target_compile_options(${PROJECT_NAME} PRIVATE -Werror=format-security)
target_compile_options(${PROJECT_NAME} PRIVATE -Werror=format-nonliteral)
target_compile_options(${PROJECT_NAME} PRIVATE -Wimplicit-fallthrough=5)
target_compile_options(${PROJECT_NAME} PRIVATE -Wno-shadow=compatible-local)
target_compile_options(${PROJECT_NAME} PRIVATE -Wno-unused-parameter)
target_compile_options(${PROJECT_NAME} PRIVATE -Wmissing-declarations)
target_compile_options(${PROJECT_NAME} PRIVATE -Wshadow=local)


# Libraries
target_link_libraries(${PROJECT_NAME} PRIVATE resolv)

find_path(ubox_include_dir libubox/md5.h)
target_include_directories(${PROJECT_NAME} PRIVATE ${ubox_include_dir})
find_library(libubox ubox)
target_link_libraries(${PROJECT_NAME} PRIVATE ${libubox})

if(${UBUS})
	target_compile_definitions(${PROJECT_NAME} PRIVATE WITH_UBUS)
	target_sources(${PROJECT_NAME} PRIVATE src/ubus.c)
	find_path(ubus_include_dir libubus.h)
	target_include_directories(${PROJECT_NAME} PRIVATE ${ubus_include_dir})
	find_library(libubus ubus)
	target_link_libraries(${PROJECT_NAME} PRIVATE ${libubus})
endif(${UBUS})

# Privilege separation: retain CAP_NET_RAW + CAP_NET_BIND_SERVICE in the
# unprivileged worker so it can re-create the DHCPv6 socket after a reset.
option(LIBCAP_NG "Drop privileges using libcap-ng" OFF)
# Unprivileged user the worker drops to (falls back to "nobody" if absent).
set(ODHCP6C_USER "nobody" CACHE STRING "Unprivileged user for the privsep worker")
if(LIBCAP_NG)
	target_compile_definitions(${PROJECT_NAME} PRIVATE WITH_LIBCAP_NG)
	target_compile_definitions(${PROJECT_NAME} PRIVATE ODHCP6C_USER="${ODHCP6C_USER}")
	find_path(capng_include_dir cap-ng.h)
	target_include_directories(${PROJECT_NAME} PRIVATE ${capng_include_dir})
	find_library(libcapng cap-ng)
	target_link_libraries(${PROJECT_NAME} PRIVATE ${libcapng})
endif(LIBCAP_NG)


# Installation
install(TARGETS ${PROJECT_NAME} DESTINATION sbin/)


# Packaging information
set(CPACK_PACKAGE_VERSION "1")
set(CPACK_PACKAGE_CONTACT "Steven Barth <steven@midlink.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_NAME}")
set(CPACK_GENERATOR "DEB;RPM;STGZ")
set(CPACK_STRIP_FILES true)
SET(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}")
include(CPack)
