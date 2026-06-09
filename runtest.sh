#!/bin/bash

workspace=$PWD

#sudo apt-get update -qq
#
#sudo apt-get install -y eatmydata
#
#sudo DEBIAN_FRONTEND=noninteractive eatmydata 			\
#	apt-get install -y					\
#	nginx nginx-dev build-essential libkrb5-dev curl	\
#	slapd ldap-utils					\
#	krb5-admin-server krb5-kdc krb5-kdc-ldap		\
#	libsasl2-modules-gssapi-mit				\
#	php-fpm php-ldap openssl				\
#	libnginx-mod-http-lua luarocks
#
#if [ ! -d "build" ]; then
#	mkdir build
#fi
#
printf "Installing Lua packages ... "
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
	libnginx-mod-http-lua luarocks cargo > /dev/null || exit 1
echo "OK"

printf "Installing PHP krb5 PECL extension build deps ... "
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
	--no-install-recommends php-dev autoconf > /dev/null || exit 1
echo "OK"

# lua-resty-ldap: the "merged" branch of Alphix's fork adds SASL/GSSAPI bind
# support needed by contrib/ldap_authz.lua, which isn't in any released
# version yet, so build and install it from a git checkout.
printf "Cloning lua-resty-ldap ... "
sudo rm -rf /tmp/lua-resty-ldap
git clone --branch merged --depth 1 https://github.com/Alphix/lua-resty-ldap.git \
	/tmp/lua-resty-ldap > /dev/null 2>&1 || exit 1
echo "OK"

printf "Building and installing lua-resty-ldap ... "
(cd /tmp/lua-resty-ldap \
	&& sudo luarocks make rockspec/lua-resty-ldap-local-0.rockspec > /dev/null 2>&1) || exit 1
echo "OK"

printf "Installing pecl-authentication-krb5 ... "
sudo pecl install krb5-1.3.0 > /dev/null 2>&1 || exit 1
echo "OK"

cd /usr/share/nginx/src
. ./conf_flags
./configure							\
	--with-cc-opt="-fPIC"					\
	--with-ld-opt="-Wl,-z,relro"				\
	"${NGX_CONF_FLAGS[@]}"					\
	--add-dynamic-module="${workspace}"			\
	--builddir="${workspace}/build"

#echo "$workspace"
#
cd $workspace

cd build
make -f "${workspace}/build/Makefile" -C /usr/share/nginx/src/ modules || exit 1
sudo mkdir -p /usr/lib/nginx/modules/
sudo cp ngx_http_auth_spnego_module.so /usr/lib/nginx/modules/ngx_http_auth_spnego_module.so
sudo mkdir -p /usr/share/nginx/modules-available/
echo "load_module modules/ngx_http_auth_spnego_module.so;" > "${workspace}/build/mod-http-auth-spnego.conf"
sudo cp "${workspace}/build/mod-http-auth-spnego.conf" /usr/share/nginx/modules-available/
sudo mkdir -p /etc/nginx/modules-enabled/
sudo ln -sf /usr/share/nginx/modules-available/mod-http-auth-spnego.conf /etc/nginx/modules-enabled/50-mod-http-auth-spnego.conf

cd ..

cd scripts
sudo rm -rf /var/log/journal/* /run/log/journal/*
sudo systemctl restart systemd-journald
sudo rm -f http_body krb5.alice.keytab krb5.mallory.keytab
sudo rm -f /etc/krb5.*
sudo rm -f /etc/nginx/sites-enabled/kerberos
sudo rm -f /tmp/krb5cc*
#sudo touch /tmp/krb5cc_nginx
#sudo chown debian:www-data /tmp/krb5cc_nginx
#sudo chmod 0664 /tmp/krb5cc_nginx
sudo rm -f /var/log/nginx/*

sudo sh ./kerberos_ldap
#sudo sh ./symlink_attack

