Summary:     FIM software provides a easy way to watch your files.
Name:        fim
Version:     0.2.0
Release:     %{_release}
License:     GPL
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://github.com/Achiefs/fim
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Achiefs, Inc <support@achiefs.com>
Packager:    Achiefs, Inc <support@achiefs.com>
AutoReqProv: no
ExclusiveOS: linux

%description
FIM helps you to monitor your files of any unwanted action.

%prep
%setup -q

curl https://sh.rustup.rs -sSf | sh -s -- -y

%build
source $HOME/.cargo/env
cargo build --release

%install
echo "localstatedir: ${_localstatedir}"
echo "RPM_BUILD_ROOT: ${RPM_BUILD_ROOT}"
mkdir -m 750 ${_localstatedir}

install -m 0750 target/release/fim ${RPM_BUILD_ROOT}/
install -m 0640 config.yml ${RPM_BUILD_ROOT}/

%pre


%post


%preun


%postun
# If the package is been uninstalled
if [ $1 = 0 ];then
  # Remove lingering folders and files
  rm -rf %{_localstatedir}
fi


%clean
rm -fr %{buildroot}

%files
%defattr(-,root,root)
%dir %attr(750, root, root) %{_localstatedir}
%attr(750, root, root) %{_localstatedir}/fim
%attr(640, root, root) %{_localstatedir}/config.yml


%changelog
* Sat Oct 02 2021 support <support@achiefs.com> - 0.2.0
- More info: https://github.com/Achiefs/fim/releases/tag/v0.2.0
