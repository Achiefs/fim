#!/bin/bash
# Dependencies: rpm-build, tar, gcc
set -ex

brand="fim"
current_dir=$(pwd)
architecture="x86_64"
rpmbuild="/usr/bin/rpmbuild"
version="$(head -n1 ../../config.yml | cut -d' ' -f2)"
bin_path="/usr/bin"
config_path="/etc/${brand}"

# Build directories
build_dir="/tmp/fim"
pkg_name="${brand}-${version}"
sources_dir="${build_dir}/${pkg_name}"
rpm_build_dir="${build_dir}/rpmbuild"
mkdir -p ${rpm_build_dir}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Prepare the sources directory to build the source tar.gz
mkdir -p ${sources_dir}
cp -R ../../* ${sources_dir}

cp ${brand}.spec ${rpm_build_dir}/SPECS/${pkg_name}.spec

# Generating source tar.gz
cd ${build_dir} && tar czf "${rpm_build_dir}/SOURCES/${pkg_name}.tar.gz" "${pkg_name}"
echo "%debug_package %{nil}" >> /root/.rpmmacros

# Building RPM
$rpmbuild --define "_topdir ${rpm_build_dir}" --define "_version ${version}" \
    --define "_bindir ${bin_path}" --define "_configdir ${config_path}" \
    --target ${architecture} -ba ${rpm_build_dir}/SPECS/${pkg_name}.spec

cp ${rpm_build_dir}/RPMS/${architecture}/${brand}*.rpm ${current_dir}/
rm -rf ${build_dir}