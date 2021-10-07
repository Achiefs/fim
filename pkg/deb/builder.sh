#!/bin/bash
# Dependencies: devscripts, equivs, debuild, tar, gcc
set -ex

install_path=$1
brand="fim"
current_dir=$(pwd)
architecture="amd64"
version="$(head -n1 ../../config.yml | cut -d' ' -f2)"

# Build directories
build_dir="/tmp/${brand}"
pkg_name="${brand}-${version}"
sources_dir="${build_dir}/${pkg_name}"

mkdir -p ${sources_dir}
cp -R ../../* ${sources_dir}
cp -pr debian ${sources_dir}/debian

# Generating directory structure to build the .deb package
cd ${build_dir} && tar -czf ${pkg_name}.orig.tar.gz "${pkg_name}"

# Configure the package with the different parameters
sed -i "s#export PATH=.*#export PATH=${PATH}#g" ${sources_dir}/debian/rules
sed -i "s:export INSTALLATION_DIR=.*:export INSTALLATION_DIR=${install_path}:g" ${sources_dir}/debian/rules
sed -i "s:DIR=\"/usr/share/fim\":DIR=\"${install_path}\":g" ${sources_dir}/debian/postrm

# Installing build dependencies
cd ${sources_dir}
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
debuild --rootcmd=sudo -b -uc -us

mv "${build_dir}/fim_${version}-1_${architecture}.deb" ${current_dir}/
#rm -rf ${build_dir}
