Summary: A high-speed clustered L2TP LNS
Name: l2tpns
Version: 2.0.2
Release: 1
Copyright: GPL
Group: System Environment/Daemons
Source: http://optusnet.dl.sourceforge.net/sourceforge/l2tpns/l2tpns-%{version}.tar.gz
URL: http://sourceforge.net/projects/l2tpns
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prereq: /sbin/chkconfig
BuildRequires: libcli >= 1.8.1
Requires: libcli >= 1.8.1

%description
A L2TP LNS which does not require l2tpd, pppd or any kernel patches. Can support
up to 65535 active sessions on a single box. Also supports ISP features like
speed throttling, walled garden, usage accounting, and more.

%prep
%setup -q

%build
make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%post
/sbin/chkconfig --add dhcpd
/sbin/chkconfig --add dhcrelay

%preun
if [ $1 = 0 ]; then     # execute this only if we are NOT doing an upgrade
    service dhcpd stop >/dev/null 2>&1
    service dhcrelay stop >/dev/null 2>&1
    /sbin/chkconfig --del dhcpd 
    /sbin/chkconfig --del dhcrelay
fi

%postun
if [ "$1" -ge "1" ]; then
    service dhcpd condrestart >/dev/null 2>&1
    service dhcrelay condrestart >/dev/null 2>&1
fi

%files
%defattr(-,root,root)
%doc Changes INSTALL INTERNALS COPYING Docs/manual.html
%dir /etc/l2tpns
%dir /usr/lib/l2tpns
%config(noreplace) /etc/l2tpns/users
%config(noreplace) /etc/l2tpns/startup-config
%config(noreplace) /etc/l2tpns/ip_pool
/usr/sbin/l2tpns
/etc/l2tpns/users

%changelog
* Thu Sep 02 2004 David Parrish <david@dparrish.com> 2.0.2
- Initial SPEC file generation

