cmake_minimum_required(VERSION 2.8)
cmake_policy(SET CMP0015 NEW)

# Project Definition
project(odhcp6c C)
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3 -std=c99")
add_definitions(-D_GNU_SOURCE -Os -Wall -Werror -pedantic)
IF(CMAKE_C_COMPILER_VERSION VERSION_GREATER 6)
	add_definitions(-Wextra -Werror=implicit-function-declaration)
	add_definitions(-Wformat -Werror=format-security -Werror=format-nonliteral)
ENDIF()
add_definitions(-Wno-unused-parameter -Wmissing-declarations)

if(${EXT_PREFIX_CLASS})
	add_definitions(-DEXT_PREFIX_CLASS=${EXT_PREFIX_CLASS})
endif(${EXT_PREFIX_CLASS})

if(${EXT_CER_ID})
	add_definitions(-DEXT_CER_ID=${EXT_CER_ID})
endif(${EXT_CER_ID})

set(SOURCES src/odhcp6c.c src/dhcpv6.c src/ra.c src/script.c src/config.c)

set(LIBRARIES resolv)

option(ENABLE_UBUS "Enable support for ubus" OFF)

if(ENABLE_UBUS)
	set(USE_LIBUBOX 1)
	add_definitions(-DHAVE_UBUS)
	set(SOURCES ${SOURCES} src/ubus.c)
	FIND_LIBRARY(ubus_lib NAMES ubus)
	set(LIBRARIES ${LIBRARIES} ${ubus_lib})
	FIND_PATH(ubus_include_dir NAMES libubus.h)
	INCLUDE_DIRECTORIES(${ubus_include_dir})
endif()

if(USE_LIBUBOX)
	add_definitions(-DUSE_LIBUBOX)
	set(LIBRARIES ${LIBRARIES} ubox)
	FIND_PATH(ubox_include_dir libubox/md5.h)
	INCLUDE_DIRECTORIES(${ubox_include_dir})
else()
	set(SOURCES ${SOURCES} src/md5.c)
endif()

add_executable(odhcp6c ${SOURCES})

target_link_libraries(odhcp6c ${LIBRARIES})

# Installation
include(GNUInstallDirs)
install(TARGETS odhcp6c DESTINATION "${CMAKE_INSTALL_SBINDIR}")

# Packaging information
set(CPACK_PACKAGE_VERSION "1")
set(CPACK_PACKAGE_CONTACT "Steven Barth <steven@midlink.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "6ac")
set(CPACK_GENERATOR "DEB;RPM;STGZ")
set(CPACK_STRIP_FILES true)

SET(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}")

include(CPack)

