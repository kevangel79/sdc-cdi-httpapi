Name:		sdc-cdi-httpapi
Version:	0.5.2
Release:	1%{?dist}
Summary:	Nagios probe for SDC CDI http-api
License:	GPLv3+
Packager:	Themis Zamani <themiszamani@gmail.com>

Source:		%{name}-%{version}.tar.gz
BuildArch:	noarch
BuildRoot:	%{_tmppath}/%{name}-%{version}
AutoReqProv: no

%description
Nagios probe to check functionality of HTTP-API service

%prep
%setup -q

%define _unpackaged_files_terminate_build 0 

%install

install -d %{buildroot}/%{_libexecdir}/argo-monitoring/probes/sdc-cdi-httpapi
install -d %{buildroot}/%{_sysconfdir}/nagios/plugins/sdc-cdi-httpapi
install -m 755 check_cdi_httpapi.py %{buildroot}/%{_libexecdir}/argo-monitoring/probes/sdc-cdi-httpapi/check_cdi_httpapi.py

%files
%dir /%{_libexecdir}/argo-monitoring
%dir /%{_libexecdir}/argo-monitoring/probes/
%dir /%{_libexecdir}/argo-monitoring/probes/sdc-cdi-httpapi

%attr(0755,root,root) /%{_libexecdir}/argo-monitoring/probes/sdc-cdi-httpapi/check_cdi_httpapi.py

%changelog
* Mon May 04 2020 Themis Zamani  <themiszamani@gmail.com> - 0.5-2
- New healthcheck
* Mon May 04 2020 Themis Zamani  <themiszamani@gmail.com> - 0.5-1
- New healthcheck
* Thu Aug 22 2019 Themis Zamani  <themiszamani@gmail.com> - 0.1-1
- Initial version of the package. 
* Thu Oct 18 2018 Mattia D'Antonio  <m.dantonio@cineca.it> - 0.1-1
- Initial version of the package. 
