$version = (gc ..\..\Cargo.toml | findstr "version" | select -First 1).split(" ")[2].trim("`"", " ")

Invoke-Expression "& `"C:\Program Files (x86)\WiX Toolset v3.11\bin\candle.exe`" .\fim.wxs -o .\fim.wixobj"

Invoke-Expression "& `"C:\Program Files (x86)\WiX Toolset v3.11\bin\light.exe`" -ext WixUIExtension .\fim.wixobj -o fim-$version-1-x64.msi"

