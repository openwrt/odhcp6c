#!/bin/bash

set -euxo pipefail
cd "${0%/*}"
cd ..

# Sanity checks
if [ ! -e "CMakeLists.txt" ] || [ ! -e "src/odhcp6c.c" ]; then
	echo "odhcp6c checkout not found" >&2
	exit 1
fi

if [ $# -eq 0 ]; then
	BUILD_ARGS=""
else
	BUILD_ARGS="$@"
fi

# Create build dirs
ODHCP6CDIR="$(pwd)"
BUILDDIR="${ODHCP6CDIR}/build"
DEPSDIR="${BUILDDIR}/depends"
[ -e "${BUILDDIR}" ] || mkdir "${BUILDDIR}"
[ -e "${DEPSDIR}" ] || mkdir "${DEPSDIR}"

# Download deps
cd "${DEPSDIR}"
[ -e "json-c" ] || git clone https://github.com/json-c/json-c.git
[ -e "libubox" ] || git clone https://github.com/openwrt/libubox.git
[ -e "ubus" ] || git clone https://github.com/openwrt/ubus.git

# Build json-c
cd "${DEPSDIR}/json-c"
cmake							\
	-S .						\
	-B .						\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	-DBUILD_SHARED_LIBS=OFF				\
	-DDISABLE_EXTRA_LIBS=ON				\
	-DBUILD_TESTING=OFF				\
	--install-prefix "${BUILDDIR}"
make
make install

# Build libubox
cd "${DEPSDIR}/libubox"
cmake							\
	-S .						\
	-B .						\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	-DBUILD_LUA=OFF					\
	-DBUILD_EXAMPLES=OFF				\
	--install-prefix "${BUILDDIR}"
make
make install

# Build ubus
cd "${DEPSDIR}/ubus"
cmake							\
	-S .						\
	-B .						\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	-DBUILD_LUA=OFF					\
	-DBUILD_EXAMPLES=OFF				\
	--install-prefix "${BUILDDIR}"
make
make install

# Build odhcp6c
cd "${ODHCP6CDIR}"
cmake							\
	-S .						\
	-B "${BUILDDIR}"				\
	-DCMAKE_PREFIX_PATH="${BUILDDIR}"		\
	-DUBUS=ON					\
	${BUILD_ARGS}
make -C "${BUILDDIR}"

set +x
echo "✅ Success - the odhcp6c binary is available at ${BUILDDIR}/odhcp6c"
echo "👷 You can rebuild odhcp6c by running 'make -C build'"

exit 0
