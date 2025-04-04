# Copyright (C) 2021, Achiefs.

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

# -----------------------------------------------------------------------------

%prep
%setup -q
curl https://sh.rustup.rs -sSf | sh -s -- -y

# -----------------------------------------------------------------------------

%build
source $HOME/.cargo/env
cargo build --release

# -----------------------------------------------------------------------------

%install
mkdir -p -m 640 ${RPM_BUILD_ROOT}%{_configdir}
mkdir -p -m 640 ${RPM_BUILD_ROOT}%{_bindir}
mkdir -p -m 640 ${RPM_BUILD_ROOT}/lib/systemd/system
mkdir -p -m 640 ${RPM_BUILD_ROOT}/usr/share/man/man1

install -m 0750 target/release/fim ${RPM_BUILD_ROOT}%{_bindir}/
install -m 0640 config/linux/config.yml ${RPM_BUILD_ROOT}%{_configdir}/
install -m 0640 config/linux/rules.yml ${RPM_BUILD_ROOT}%{_configdir}/
install -m 0640 config/index_template.json ${RPM_BUILD_ROOT}%{_configdir}/
install -m 0644 pkg/fim.service ${RPM_BUILD_ROOT}/lib/systemd/system/
install -m 0644 pkg/fim.1 ${RPM_BUILD_ROOT}/usr/share/man/man1/

# -----------------------------------------------------------------------------

%pre

# -----------------------------------------------------------------------------

%post

# -----------------------------------------------------------------------------

%preun
if [ $1 = 0 ];then
    echo -n "Stopping FIM service..."
    if command -v systemctl > /dev/null 2>&1 && systemctl is-active --quiet %{name} > /dev/null 2>&1; then
        systemctl --no-reload stop %{name}.service > /dev/null 2>&1
        systemctl disable %{name} > /dev/null 2>&1
        systemctl daemon-reload > /dev/null 2>&1
    fi
    echo " OK"
fi

# -----------------------------------------------------------------------------

%postun

# -----------------------------------------------------------------------------

%posttrans
if systemctl is-active --quiet %{name} > /dev/null 2>&1; then
    echo -n "Restarting FIM process to reload configuration..."
    if command -v systemctl > /dev/null 2>&1; then
        systemctl daemon-reload > /dev/null 2>&1
        systemctl restart %{name}.service > /dev/null 2>&1
    fi
    echo " OK"
fi

# -----------------------------------------------------------------------------

%clean
rm -fr %{buildroot}

# -----------------------------------------------------------------------------

%files
%defattr(-,root,root)
%attr(750, root, root) %{_bindir}/fim
%dir %attr(750, root, root) %{_configdir}
%attr(640, root, root) %config(noreplace) %{_configdir}/config.yml
%attr(640, root, root) %config(noreplace) %{_configdir}/rules.yml
%attr(640, root, root) %{_configdir}/index_template.json
%attr(644, root, root) /lib/systemd/system/fim.service
%attr(644, root, root) /usr/share/man/man1/fim.1.gz

# -----------------------------------------------------------------------------

%changelog
* Mon Mar 31 2025 support <support@achiefs.com> - 0.6.0
- More info: https://github.com/Achiefs/fim/releases/tag/v0.6.0

* Wed Jan 15 2025 support <support@achiefs.com> - 0.5.2
- More info: https://github.com/Achiefs/fim/releases/tag/v0.5.2

* Thu Oct 10 2024 support <support@achiefs.com> - 0.5.1
- More info: https://github.com/Achiefs/fim/releases/tag/v0.5.1

* Tue Apr 30 2024 support <support@achiefs.com> - 0.5.0
- More info: https://github.com/Achiefs/fim/releases/tag/v0.5.0

* Fri Apr 19 2024 support <support@achiefs.com> - 0.4.11
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.11

* Tue Oct 31 2023 support <support@achiefs.com> - 0.4.10
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.10

* Fri Sep 08 2023 support <support@achiefs.com> - 0.4.9
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.9

* Fri Jul 21 2023 support <support@achiefs.com> - 0.4.8
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.8

* Fri May 26 2023 support <support@achiefs.com> - 0.4.7
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.7

* Tue Mar 21 2023 support <support@achiefs.com> - 0.4.6
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.6

* Sat Feb 18 2023 support <support@achiefs.com> - 0.4.5
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.5

* Tue Feb 14 2023 support <support@achiefs.com> - 0.4.4
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.4

* Mon Dec 19 2022 support <support@achiefs.com> - 0.4.3
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.3

* Tue Dec 13 2022 support <support@achiefs.com> - 0.4.2
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.2

* Tue Oct 25 2022 support <support@achiefs.com> - 0.4.1
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.1

* Sat Jul 02 2022 support <support@achiefs.com> - 0.4.0
- More info: https://github.com/Achiefs/fim/releases/tag/v0.4.0

* Wed Jun 01 2022 support <support@achiefs.com> - 0.3.1
- More info: https://github.com/Achiefs/fim/releases/tag/v0.3.1

* Wed May 18 2022 support <support@achiefs.com> - 0.3.0
- More info: https://github.com/Achiefs/fim/releases/tag/v0.3.0

* Fri Feb 25 2022 support <support@achiefs.com> - 0.2.1
- More info: https://github.com/Achiefs/fim/releases/tag/v0.2.1

* Tue Oct 05 2021 support <support@achiefs.com> - 0.2.0
- More info: https://github.com/Achiefs/fim/releases/tag/v0.2.0
