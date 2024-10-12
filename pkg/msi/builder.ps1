$version = (gc ..\..\Cargo.toml | findstr "version" | select -First 1).split(" ")[2].trim("`"", " ")

(Get-Content .\filemonitor.wxs) -replace 'FIM_VERSION', $version | Set-Content -NoNewLine filemonitor.wxs

cd ..\..\
cargo build --release
cd pkg\msi

cp ..\..\target\release\filemonitor.exe .\
cp ..\..\config\windows\config.yml .\
cp ..\..\config\windows\rules.yml .\

Invoke-Expression "& `"C:\Program Files (x86)\WiX Toolset v3.*\bin\candle.exe`" .\filemonitor.wxs -o .\filemonitor.wixobj"

Invoke-Expression "& `"C:\Program Files (x86)\WiX Toolset v3.*\bin\light.exe`" -ext WixUIExtension .\filemonitor.wixobj -o filemonitor-$version-1-x64.msi"

