#!/bin/bash

# Dependencies: rpm-build, tar, gcc

set -ex

install_path=$1
current_dir=$(pwd)
architecture_target="x86_64"
release="1"
rpmbuild="/usr/bin/rpmbuild"
version="$(head -n1 ../../config.yml | cut -d' ' -f2)"

# Build directories
build_dir="/tmp/build"
rpm_build_dir="${build_dir}/rpmbuild"
file_name="fim-${version}-${release}"
rpm_file="${file_name}.${architecture_target}.rpm"
pkg_path="${rpm_build_dir}/RPMS/${architecture_target}"
extract_path="${pkg_path}"
mkdir -p ${rpm_build_dir}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Prepare the sources directory to build the source tar.gz
package_name="fim-${version}"
mkdir ${build_dir}/${package_name}
cp -R ../../* ${build_dir}/${package_name}

cp fim.spec ${rpm_build_dir}/SPECS/${package_name}.spec

# Generating source tar.gz
cd ${build_dir} && tar czf "${rpm_build_dir}/SOURCES/${package_name}.tar.gz" "${package_name}"
echo "%debug_package %{nil}" >> /root/.rpmmacros

# Building RPM
$linux $rpmbuild --define "_sysconfdir /etc" --define "_topdir ${rpm_build_dir}" \
        --define "_version ${version}" --define "_release ${release}" \
        --define "_localstatedir ${install_path}" --target ${architecture_target} \
        -ba ${rpm_build_dir}/SPECS/${package_name}.spec

cp ${rpm_build_dir}/RPMS/${architecture_target}/fim*.rpm ${current_dir}/
rm -rf ${build_dir}