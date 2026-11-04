Name:           fingerprint-fpc
Version:        1.0.0
Release:        1%{?dist}
Summary:        High-reliability FPC 10a5:9201 / 10a5:a900 fingerprint daemon
License:        GPL-3.0-or-later
URL:            https://github.com/zhanmq-artforge/fingerprint-fpc
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.75
BuildRequires:  cargo
BuildRequires:  libusb1-devel
BuildRequires:  openssl-devel
BuildRequires:  pkgconfig

Requires:       dbus
Requires:       libusb1
Requires:       openssl
Conflicts:      fprintd
Provides:       fprintd

%description
High-reliability, memory-safe Linux D-Bus driver for FPC (Fingerprint Cards AB)
sensors (USB IDs 10a5:9201 and 10a5:a900), commonly found in Xiaomi / RedmiBook
laptops. Implements the net.reactivated.Fprint specification with hardware
TLS-PSK tunneling, auto-reconnection self-healing, and D-Bus on-demand activation.

%prep
%autosetup

%build
cargo build --release

%install
rm -rf %{buildroot}
install -D -p -m 0755 target/release/fingerprint-fpc %{buildroot}%{_bindir}/fingerprint-fpc
install -D -p -m 0644 fingerprint-fpc.service %{buildroot}%{_unitdir}/fingerprint-fpc.service
install -D -p -m 0644 dbus/net.reactivated.Fprint.service %{buildroot}%{_datadir}/dbus-1/system-services/net.reactivated.Fprint.service
install -D -p -m 0644 dbus/net.reactivated.Fprint.conf %{buildroot}%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.conf
install -D -p -m 0644 polkit/net.reactivated.fprint.policy %{buildroot}%{_datadir}/polkit-1/actions/net.reactivated.fprint.policy
install -d -m 0700 %{buildroot}%{_sharedstatedir}/fprint

%post
# Mask stock fprintd to avoid D-Bus conflicts
if systemctl list-unit-files | grep -q "^fprintd.service"; then
    systemctl stop fprintd &>/dev/null || :
    systemctl mask fprintd &>/dev/null || :
fi
mkdir -p %{_sharedstatedir}/fprint
chmod 0700 %{_sharedstatedir}/fprint
systemctl daemon-reload &>/dev/null || :
systemctl enable --now fingerprint-fpc.service &>/dev/null || :

%preun
if [ $1 -eq 0 ]; then
    systemctl stop fingerprint-fpc.service &>/dev/null || :
    systemctl disable fingerprint-fpc.service &>/dev/null || :
fi

%postun
if [ $1 -eq 0 ]; then
    systemctl unmask fprintd &>/dev/null || :
    systemctl daemon-reload &>/dev/null || :
fi

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/fingerprint-fpc
%{_unitdir}/fingerprint-fpc.service
%{_datadir}/dbus-1/system-services/net.reactivated.Fprint.service
%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.conf
%{_datadir}/polkit-1/actions/net.reactivated.fprint.policy
%dir %attr(0700, root, root) %{_sharedstatedir}/fprint
