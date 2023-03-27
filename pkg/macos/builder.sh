#!/bin/sh

current_dir=$(pwd)
base_dir="${current_dir}/../../"
version="$(grep -m1 'version' ${base_dir}/Cargo.toml | cut -d' ' -f3 | tr -d '"')"
architecture="$(uname -m)"


app_dir="${current_dir}/files/Applications/FileMonitor.app"

cd ../../
cargo build --release

mkdir -p "${app_dir}"
cp ./target/release/fim "${app_dir}/"
cp ./config/macos/config.yml "${app_dir}"

cd "${current_dir}"
chmod 0755 ./Scripts/postinstall
sed "s|VERSION|${version}|g" ./distribution.xml > ./distribution.sed
mv ./distribution.sed ./distribution.xml
sed "s|ARCHITECTURE|${architecture}|g" ./distribution.xml > ./distribution.sed
mv ./distribution.sed ./distribution.xml

pkgbuild  --root ./files \
          --scripts ./Scripts \
          --identifier com.Achiefs.fim \
          --version "${version}" \
          --install-location / \
          fim.pkg

productbuild  --distribution ./distribution.xml \
              --resources Resources \
              --package-path ./fim.pkg \
              fim-"${version}-${architecture}".pkg

rm -rf fim.pkg

if [ "$1" = "-s" ]; then
    productsign --sign "$2" \
    fim-"${version}-${architecture}".pkg \
    fim-"${version}-${architecture}"-signed.pkg
fi