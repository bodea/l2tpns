Summary: A high-speed clustered L2TP LNS
Name: l2tpns
Version: 2.0.10
Release: 1
Copyright: GPL
Group: System Environment/Daemons
Source: http://optusnet.dl.sourceforge.net/sourceforge/l2tpns/l2tpns-%{version}.tar.gz
URL: http://sourceforge.net/projects/l2tpns
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prereq: /sbin/chkconfig
BuildRequires: libcli >= 1.8.2
Requires: libcli >= 1.8.2

%description
l2tpns is a layer 2 tunneling protocol network server (LNS).  It
supports up to 65535 concurrent sessions per server/cluster plus ISP
features such as rate limiting, walled garden, usage accounting, and
more.

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
%doc Changes INSTALL INTERNALS COPYING THANKS Docs/manual.html
%dir /etc/l2tpns
%config(noreplace) /etc/l2tpns/users
%config(noreplace) /etc/l2tpns/startup-config
%config(noreplace) /etc/l2tpns/ip_pool
%attr(755,root,root) /usr/sbin/*
%attr(755,root,root) /usr/lib/l2tpns
%attr(644,root,root) /usr/share/man/man[58]/*

%changelog
* Wed Dec  1 2004 Brendan O'Dea <bod@optusnet.com.au> 2.0.10-1
- 2.0.10 release, see /usr/share/doc/l2tpns-2.0.10/Changes
