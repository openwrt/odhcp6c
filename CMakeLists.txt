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
	src/script_codec.c
	src/script_common.c
	src/script_worker.c
	src/script_monitor.c
	src/seccomp.c
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


# Exploit-mitigation build flags (defense-in-depth)
#
# These raise the cost of exploiting any residual memory-safety bug in this
# network-facing root daemon. They are enabled by default but kept fully
# overridable: distro/OpenWrt build systems usually inject their own hardening
# and can disable these with -DHARDENING=OFF, in which case the build is
# identical to having no mitigation flags at all. Every flag is feature-detected
# so a toolchain lacking any one of them still configures and builds.
option(HARDENING "Enable exploit-mitigation build flags" ON)

if(HARDENING)
	include(CheckCCompilerFlag)

	# CheckLinkerFlag is available on CMake >= 3.18; fall back to a compiler
	# check that forwards the flag to the linker on older CMake.
	if(NOT CMAKE_VERSION VERSION_LESS 3.18)
		include(CheckLinkerFlag)
	endif()

	# Add a compile flag only if the compiler accepts it.
	function(odhcp6c_try_compile_option flag)
		string(MAKE_C_IDENTIFIER "CC_HAS_${flag}" _var)
		check_c_compiler_flag("${flag}" ${_var})
		if(${_var})
			target_compile_options(${PROJECT_NAME} PRIVATE ${flag})
		endif()
	endfunction()

	# Add a link flag only if the linker accepts it.
	function(odhcp6c_try_link_option flag)
		string(MAKE_C_IDENTIFIER "LD_HAS_${flag}" _var)
		if(COMMAND check_linker_flag)
			check_linker_flag(C "${flag}" ${_var})
		else()
			set(CMAKE_REQUIRED_LINK_OPTIONS "${flag}")
			check_c_compiler_flag("" ${_var})
			unset(CMAKE_REQUIRED_LINK_OPTIONS)
		endif()
		if(${_var})
			target_link_options(${PROJECT_NAME} PRIVATE ${flag})
		endif()
	endfunction()

	# Code-generation mitigations.
	odhcp6c_try_compile_option(-fstack-protector-strong)
	odhcp6c_try_compile_option(-fstack-clash-protection)
	odhcp6c_try_compile_option(-fPIE)

	# _FORTIFY_SOURCE requires an optimization level (the project sets -Os).
	# Prefer level 3 where the toolchain supports it, otherwise level 2.
	# -U_FORTIFY_SOURCE is prepended to avoid -Werror-fatal redefinition
	# warnings when the toolchain (or outer build) already defines it.
	# check_c_source_compiles() is used instead of check_c_compiler_flag()
	# so that libc headers are included in the probe: merely accepting the
	# -D flag is not enough; the fortified prototypes must also compile
	# without error or warning (the -Werror probe flag mirrors the
	# project's own -Werror build requirement).
	include(CheckCSourceCompiles)
	foreach(_fortify_level 3 2)
		set(CMAKE_REQUIRED_FLAGS "-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=${_fortify_level} -Werror")
		check_c_source_compiles(
			"#include <string.h>\nint main(void) { return 0; }"
			CC_HAS_FORTIFY_SOURCE_${_fortify_level}
		)
		unset(CMAKE_REQUIRED_FLAGS)
		if(CC_HAS_FORTIFY_SOURCE_${_fortify_level})
			target_compile_options(${PROJECT_NAME} PRIVATE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=${_fortify_level})
			break()
		endif()
	endforeach()

	# Link-time mitigations: PIE, full RELRO and a non-executable stack.
	odhcp6c_try_link_option(-pie)
	odhcp6c_try_link_option(-Wl,-z,relro)
	odhcp6c_try_link_option(-Wl,-z,now)
	odhcp6c_try_link_option(-Wl,-z,noexecstack)
endif()


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
	find_library(libcapng cap-ng)
	if(NOT capng_include_dir OR NOT libcapng)
		message(FATAL_ERROR "LIBCAP_NG=ON but libcap-ng was not found (install libcap-ng-dev or disable LIBCAP_NG)")
	endif()
	target_include_directories(${PROJECT_NAME} PRIVATE ${capng_include_dir})
	target_link_libraries(${PROJECT_NAME} PRIVATE ${libcapng})
endif(LIBCAP_NG)

# Seccomp-BPF confinement: restrict the network-facing privsep worker to a
# minimal syscall allow-list via libseccomp. Opt-in; with SECCOMP=OFF (default)
# seccomp_apply() is a no-op and no extra link dependency is added.
option(SECCOMP "Confine the worker with a seccomp-BPF syscall filter" OFF)
# Make a failed filter load non-fatal (warn + continue) for bring-up on new
# architectures. Default is fail-closed: the worker exits if the filter cannot
# be loaded.
option(SECCOMP_FAIL_OPEN "Continue unconfined if the seccomp filter fails to load" OFF)
if(SECCOMP)
	target_compile_definitions(${PROJECT_NAME} PRIVATE WITH_SECCOMP)
	if(SECCOMP_FAIL_OPEN)
		target_compile_definitions(${PROJECT_NAME} PRIVATE WITH_SECCOMP_FAIL_OPEN)
	endif(SECCOMP_FAIL_OPEN)
	find_path(seccomp_include_dir seccomp.h)
	find_library(libseccomp seccomp)
	if(NOT seccomp_include_dir OR NOT libseccomp)
		message(FATAL_ERROR "SECCOMP=ON but libseccomp was not found (install libseccomp-dev or disable SECCOMP)")
	endif()
	target_include_directories(${PROJECT_NAME} PRIVATE ${seccomp_include_dir})
	target_link_libraries(${PROJECT_NAME} PRIVATE ${libseccomp})
endif(SECCOMP)


# Fuzzing: build a libFuzzer target for the pure privilege-separation request
# codec (script_req_decode). Opt-in and self-contained -- it links ONLY the pure
# codec translation unit plus a tiny harness, so a normal build is completely
# unaffected and the fuzzer pulls in no sockets, fork/exec or daemon state.
# Requires a libFuzzer-capable compiler (e.g. clang -fsanitize=fuzzer).
option(FUZZING "Build the libFuzzer target for the privsep request codec" OFF)
if(FUZZING)
	add_executable(script_req_fuzz
		src/script_codec.c
		tools/fuzz/script_req_fuzz.c
	)
	set_target_properties(script_req_fuzz PROPERTIES C_STANDARD 11)
	target_compile_definitions(script_req_fuzz PRIVATE _GNU_SOURCE)
	target_include_directories(script_req_fuzz PRIVATE src)
	target_compile_options(script_req_fuzz PRIVATE
		-g -fsanitize=fuzzer,address,undefined)
	target_link_options(script_req_fuzz PRIVATE
		-fsanitize=fuzzer,address,undefined)
endif(FUZZING)


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
