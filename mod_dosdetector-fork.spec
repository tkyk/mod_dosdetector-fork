%define name	%{mod_name}-fork
%define version %{mod_version}
%define release 0.1.b2
%define github_user tkyk

# Module-Specific definitions
%define mod_version	1.1.0
%define mod_basename	dosdetector
%define mod_name	mod_%{mod_basename}
%define mod_conf	%{mod_basename}.conf
%define mod_so		%{mod_name}.so
%define sourcename	%{name}-%{mod_version}
%define apxs_path	/usr/sbin

Summary:	DoS attack detector for the Apache web server
Name:		%{name}
Version:	%{version}
Release:	%{release}
License:	MIT License
Group:		System Environment/Daemons
URL:		http://github.com/%{github_user}/mod_dosdetector-fork/tree/master
Source0:	http://cloud.github.com/downloads/%{github_user}/mod_dosdetector-fork/%{sourcename}.tar.gz

BuildRoot:	%{_tmppath}/%{name}-buildroot
BuildRequires:	sed, httpd-devel >= 2.4, apr-devel
Provides:	mod_dosdetector
Requires:	httpd >= 2.4

%description
mod_dosdetector is a DoS detector module for Apache HTTP Server.

%prep
%setup -q

%build
%{__make} PATH=%{apxs_path}:$PATH
%{__sed} 's/^\#LoadModule/LoadModule/' %{mod_basename}-sample.conf > %{mod_conf}

%install
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}
%{__install} -d %{buildroot}%{_libdir}/httpd/modules/
%{__install} -d %{buildroot}%{_sysconfdir}/httpd/conf.d/
%{__install} -m0755 .libs/%{mod_so} %{buildroot}%{_libdir}/httpd/modules/
%{__install} -m0644 %{mod_conf} %{buildroot}%{_sysconfdir}/httpd/conf.d/

%clean
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

%post

%postun

%files
%defattr(-,root,root)
%{_libdir}/httpd/modules/%{mod_so}
%config(noreplace) %{_sysconfdir}/httpd/conf.d/%{mod_conf}

%changelog
* Mon Aug 17 2009 Takayuki Miwa <i@tkyk.name> - 1.0.0-1
- Initial package.

