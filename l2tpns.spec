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

%files
%defattr(-,root,root)
%doc Changes INSTALL INTERNALS COPYING Docs/manual.html
%dir /etc/l2tpns
%config(noreplace) /etc/l2tpns/users
%config(noreplace) /etc/l2tpns/startup-config
%config(noreplace) /etc/l2tpns/ip_pool
%attr(700,root,root) /usr/sbin/l2tpns
%attr(755,root,root) /usr/lib/l2tpns

%changelog
* Thu Sep 02 2004 David Parrish <david@dparrish.com> 2.0.2
- Initial SPEC file generation