#!/bin/bash
# Dependencies: curl, devscripts, equivs, debuild, tar, gcc
set -ex

install_path=$1
brand="fim"
target_dir=$(dirname $0)
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
#cp -pr ${target_dir}/debian ${sources_dir}/debian

# Generating directory structure to build the .deb package
cd ${build_dir} && tar -czf ${pkg_name}.orig.tar.gz "${pkg_name}"

# Configure the package with the different parameters
sed -i "s|export BRAND=.*|export BRAND=${brand}|g" ${pkg_dir}/debian/rules
sed -i "s|export BUILD_DIR=.*|export BUILD_DIR=${sources_dir}|g" ${pkg_dir}/debian/rules
sed -i "s|export INSTALL_DIR=.*|export INSTALL_DIR=${install_path}|g" ${pkg_dir}/debian/rules
sed -i "s|INSTALL_DIR=\"/usr/share/fim\"|INSTALL_DIR=\"${install_path}\"|g" ${pkg_dir}/debian/postrm

# Installing build dependencies
cd ${pkg_dir}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
debuild -b -uc -us

mv "${pkg_dir}/../${brand}_${version}_${architecture}.deb" ${target_dir}/
#rm -rf ${build_dir}
