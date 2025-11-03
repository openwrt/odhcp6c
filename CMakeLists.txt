cmake_minimum_required(VERSION 3.13)
cmake_policy(SET CMP0015 NEW)


# Project Definition
project(odhcp6c LANGUAGES C)
add_executable(${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE
	src/odhcp6c.c
	src/dhcpv6.c
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
target_compile_options(${PROJECT_NAME} PRIVATE -Wno-unused-parameter)
target_compile_options(${PROJECT_NAME} PRIVATE -Wmissing-declarations)


# Libraries
target_link_libraries(${PROJECT_NAME} PRIVATE resolv)

if (${USE_LIBUBOX})
	target_compile_definitions(${PROJECT_NAME} PRIVATE USE_LIBUBOX)
	find_path(ubox_include_dir libubox/md5.h)
	target_include_directories(${PROJECT_NAME} PRIVATE ${ubox_include_dir})
	find_library(libubox ubox)
	target_link_libraries(${PROJECT_NAME} PRIVATE ${libubox})
else (${USE_LIBUBOX})
	target_sources(${PROJECT_NAME} PRIVATE src/md5.c)
endif(${USE_LIBUBOX})


# Optional Features
if (${EXT_CER_ID})
	target_compile_definitions(${PROJECT_NAME} PRIVATE EXT_CER_ID=${EXT_CER_ID})
endif(${EXT_CER_ID})


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
