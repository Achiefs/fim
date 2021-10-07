Summary:     FIM software provides a easy way to watch your files.
Name:        fim
Version:     %{_version}
Release:     1
License:     GPL
Group:       System Environment/Daemons
Source0:     %{name}-%{version}.tar.gz
URL:         https://github.com/Achiefs/fim
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Vendor:      Achiefs <support@achiefs.com>
Packager:    Jose Fernandez <support@achiefs.com>
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
mkdir -p -m 750 ${RPM_BUILD_ROOT}%{_localstatedir}
install -m 0750 target/release/fim ${RPM_BUILD_ROOT}%{_localstatedir}/
install -m 0640 config.yml ${RPM_BUILD_ROOT}%{_localstatedir}/

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
* Tue Oct 05 2021 support <support@achiefs.com> - 0.2.0
- More info: https://github.com/Achiefs/fim/releases/tag/v0.2.0
