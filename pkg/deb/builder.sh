#!/bin/bash
# Dependencies: curl, devscripts, equivs, tar, gcc
set -ex

brand="fim"
target_dir=$(pwd)
architecture="amd64"
base_dir="${target_dir}/../../"
version="$(head -n1 ${base_dir}/config.yml | cut -d' ' -f2)"

# Build directories
build_dir="/tmp/${brand}"
pkg_name="${brand}-${version}"
sources_dir="${build_dir}/${pkg_name}"
pkg_dir="${sources_dir}/pkg/deb"

mkdir -p ${sources_dir}
cp -R ${base_dir}/* ${sources_dir}/

# Generating directory structure to build the .deb package
cd ${build_dir} && tar -czf ${pkg_name}.orig.tar.gz "${pkg_name}"

# Installing build dependencies
cd ${pkg_dir}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
debuild -b -uc -us

mv "${pkg_dir}/../${brand}_${version}_${architecture}.deb" ${target_dir}/
rm -rf ${build_dir}
