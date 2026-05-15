Nginx module for HTTP SPNEGO auth
=================================

This module implements adds [SPNEGO](http://tools.ietf.org/html/rfc4178)
support to nginx(http://nginx.org).  It currently supports only Kerberos
authentication via [GSSAPI](http://en.wikipedia.org/wiki/GSSAPI)

Prerequisites
-------------

Authentication has been tested with (at least) the following:

* Nginx 1.2 through 1.15
* Internet Explorer 8 and above
* Firefox 10 and above
* Chrome 20 and above
* Curl 7.x (GSS-Negotiate), 7.x (SPNEGO/fbopenssl)

The underlying kerberos library used for these tests was MIT KRB5 v1.12.


Installation from source
------------------------

1. Download [nginx source](http://www.nginx.org/en/download.html)
1. Extract to a directory
1. Clone this module into the directory
1. Follow the [nginx install documentation](http://nginx.org/en/docs/install.html)
and pass an `--add-module` option to nginx configure:

    ./configure --add-module=spnego-http-auth-nginx-module

Note that if it isn't clear, you do need KRB5 (MIT or Heimdal) header files installed.  On Debian based distributions, including Ubuntu, this is the krb5-multidev, libkrb5-dev, heimdal-dev, or heimdal-multidev package depending on your environment.  On other Linux distributions, you want the development libraries that provide gssapi_krb5.h.

Installation from distro packages
---------------------------------

Binary packages are available from the following Linux distros:

* [Debian](https://packages.debian.org/libnginx-mod-http-auth-spnego) - `apt-get install libnginx-mod-http-auth-spnego`
* [Ubuntu](https://packages.ubuntu.com/libnginx-mod-http-auth-spnego) - `apt-get install libnginx-mod-http-auth-spnego`

Configuration reference
-----------------------

You can configure GSS authentication on a per-location and/or a global basis:

The following options are mandatory:
* `auth_gss`: on/off, for ease of unsecuring while leaving other options in
  the config file.

The following options are optional but commonly needed:
* `auth_gss_keytab`: absolute path to the keytab file containing service
  credentials. Defaults to `/etc/krb5.keytab`.
* `auth_gss_service_name`: service principal name to use when acquiring
  credentials.  When the server is accessed via a DNS CNAME, this should be
  set to the full `service/canonical-hostname` form (e.g.
  `HTTP/webserver01.example.com`) matching the keytab entry and the A/AAAA
  record, not the CNAME alias — Kerberos clients typically resolve CNAMEs
  before requesting a service ticket.

The following option should normally not be necessary:
* `auth_gss_realm`: Kerberos realm name. In most deployments this should not
  be set — the realm is negotiated automatically and misconfiguring it is a
  common source of authentication failures. If set, the realm is only included
  in the nginx variable `$remote_user` if it differs from this value.
  To override this behavior, set `auth_gss_format_full` to `on` in your
  configuration.

If you would like to authorize only a specific set of principals, you can use the
`auth_gss_authorized_principal` and/or `auth_gss_authorized_principal_regex` options
(multiple entries are supported, one per line):
* `auth_gss_authorized_principal`: a principal name as a string, e.g. `alice@EXAMPLE.COM`.
* `auth_gss_authorized_principal_regex`: a regex to match against, e.g.
  `^.*/admin@EXAMPLE.COM$`.

The remote user header in nginx can only be set by doing basic authentication.
Thus, this module sets a bogus basic auth header which will be visible to your backend
application. The easiest way to hide this bogus header is to add the following configuration
to your location config:

    proxy_set_header Authorization "";

A future version of the module may make this behavior an option, but this should
be a sufficient workaround for now.

If you would like to enable GSS local name rules to rewrite usernames, you can
specify the `auth_gss_map_to_local` option.

Credential Delegation
-----------------------------

User credentials can be delegated to nginx using the `auth_gss_delegate_credentials`
directive. It accepts three values:

* `off` — delegation disabled (default).
* `on` — delegated credentials are written to a temporary ccache file under the
  system tmp directory and exposed via the `$krb5_cc_name` nginx variable.
* `export` — delegated credentials are exported in-memory via `gss_export_cred()`,
  base64-encoded, and exposed via the `$krb5_cred_exported` nginx variable.  No
  file is written.  See the Security Considerations section below before using
  this mode.

Constrained delegation (S4U2Proxy) can be enabled with the
`auth_gss_constrained_delegation` directive alongside `auth_gss_delegate_credentials`.
`auth_gss_service_ccache` specifies the ccache file used to hold the server's own
TGT for S4U2Proxy; if omitted, the process default ccache is used.
`auth_gss_service_ccache_memory on` replaces the file-based service ccache with
an in-memory ccache; see the Service Ccache section below.

**File-based mode** (`on`):

    auth_gss_service_ccache /tmp/krb5cc_nginx;
    auth_gss_delegate_credentials on;
    auth_gss_constrained_delegation on;
    fastcgi_param KRB5CCNAME $krb5_cc_name;

The delegated credentials file is destroyed once the request completes.

**Export mode** (`export`):

    auth_gss_service_ccache /tmp/krb5cc_nginx;
    auth_gss_delegate_credentials export;
    auth_gss_constrained_delegation on;
    fastcgi_param KRB5_CRED_EXPORTED $krb5_cred_exported;

No per-request file is created.  The credential blob is passed directly to the
FastCGI backend as a base64-encoded parameter.

**Fully file-free mode** (export + memory service ccache):

    auth_gss_service_ccache_memory on;
    auth_gss_delegate_credentials export;
    auth_gss_constrained_delegation on;
    fastcgi_param KRB5_CRED_EXPORTED $krb5_cred_exported;

No files are written at any point.  See the Service Ccache and Security
Considerations sections below.

Constrained delegation is currently only supported using the Negotiate authentication
scheme and has only been tested with MIT Kerberos (use at your own risk with Heimdal).

Service Ccache (`auth_gss_service_ccache_memory`)
-------------------------------------------------

When `auth_gss_service_ccache_memory on` is set, the HTTP service principal's
TGT is held in a per-worker in-memory ccache rather than a file.  The
`auth_gss_service_ccache` file path directive is then ignored.

**Implementation.**  Each nginx worker maintains one MEMORY ccache per service
principal, named `MEMORY:nginx_svc_<principal>` (e.g.
`MEMORY:nginx_svc_HTTP/server.example.com@EXAMPLE.COM`).  MIT Kerberos MEMORY
ccaches are identified by an arbitrary string; `/`, `@`, and `.` are valid in
the name.  Naming by principal means a worker handling multiple locations with
different service principals gets one independent MEMORY ccache per principal
with no interference between them.

Because MEMORY ccaches are per-process (not shared between workers), the
cross-worker mutex used by the file-based path to serialise TGT refresh is
not needed.  Each worker independently checks its own ccache and fetches a new
TGT from the keytab when needed.  When a TGT expires all N workers each make
one independent TGS-REQ rather than one worker doing it for all.  For typical
TGT lifetimes (24 h) and worker counts (4–16), this is negligible.

**Security tradeoffs.**

*Improvements over file-based service ccache:*

* The TGT never appears on disk; there is no file to read or steal.
* No predictable filename for an attacker to target.
* The TGT vanishes automatically when a worker exits — no orphaned files.
* Per-worker isolation: a memory-disclosure exploit affecting one worker does
  not expose the TGT of any other worker.

*Considerations:*

* If nginx worker processes generate core dumps (disabled by default via
  `setrlimit(RLIMIT_CORE, 0)`) the TGT would be present in the dump.
* On nginx restart or graceful reload every worker must fetch a fresh TGT from
  the KDC.  With file-based ccaches a valid TGT can survive a restart.  If the
  KDC is unreachable at restart time, S4U2Proxy will fail until connectivity
  is restored.  This is an availability consideration, not a security one.

The service TGT is a lower-value credential than the per-request user TGTs
handled by `auth_gss_delegate_credentials`: it can only be used to perform
S4U2Proxy to the services listed in `krbAllowedToDelegateTo`, not to
impersonate arbitrary users.

Security Considerations for Export Mode
----------------------------------------

Export mode eliminates the temporary ccache file under `/tmp`, removing the risk of
credential files being read by other local processes, TOCTOU races, and orphaned
files left behind on worker crashes.  However, it introduces its own tradeoffs:

**Debug logging.**  When nginx is compiled with `--with-debug` and
`error_log ... debug` is active, nginx logs FastCGI parameters at debug level.
This includes `KRB5_CRED_EXPORTED`, which contains a live, base64-encoded Kerberos
credential blob.  Anyone with access to the error log can extract and use it.
**Do not enable debug-level logging in production when using export mode.**

**FastCGI transport.**  The credential blob travels over the FastCGI connection
between nginx and php-fpm.  Use a Unix socket for this connection.  A cleartext
TCP socket — even on loopback — allows any process on the host with sufficient
privilege (e.g. packet capture) to intercept the credential.

**FastCGI buffer size.**  An exported Kerberos credential is typically 2–8 KB of
binary data, which becomes 3–11 KB when base64-encoded.  If nginx's
`fastcgi_buffer_size` is at its default of 4 KB you may need to increase it:

    fastcgi_buffer_size 16k;

Basic authentication fallback
-----------------------------

The module falls back to basic authentication by default if no negotiation is
attempted by the client.  If you are using SPNEGO without SSL, it is recommended
you disable basic authentication fallback, as the password would be sent in
plaintext.  This is done by setting `auth_gss_allow_basic_fallback` in the
config file.

    auth_gss_allow_basic_fallback off

These options affect the operation of basic authentication:
* `auth_gss_realm`: Kerberos realm name.  If this is specified, the realm is
  only passed to the nginx variable $remote_user if it differs from this
  default.  To override this behavior, set *auth_gss_format_full* to 1 in your
  configuration.
* `auth_gss_force_realm`: Forcibly authenticate using the realm configured in
  `auth_gss_realm` or the system default realm if `auth_gss_realm` is not set.
  This will rewrite $remote_user if the client provided a different realm.  If
  *auth_gss_format_full* is not set, $remote_user will not include a realm even
  if one was specified by the client.


Channel Bindings
----------------

The `auth_gss_channel_bindings` directive binds a Kerberos authentication
exchange to the TLS session it travels over, preventing a man-in-the-middle
from relaying a valid Negotiate token to a different server.  The directive
has no effect on plain HTTP connections (it degrades gracefully to no
bindings).

    auth_gss_channel_bindings off;              # default – existing behaviour
    auth_gss_channel_bindings server-end-point; # RFC 5929 – hash of server cert
    auth_gss_channel_bindings exporter;         # RFC 9266 – TLS keying material (tech demo)

**`server-end-point`** (RFC 5929) hashes the server's TLS certificate using
the certificate's own signature algorithm (SHA-256 minimum).  This is the
type supported by Windows EPA clients and by curl ≥ 8.10.0 when built against
OpenSSL.  It is valid for both TLS 1.2 and TLS 1.3.

**`exporter`** (RFC 9266) derives 32 bytes from the TLS keying material
exporter with label `EXPORTER-Channel-Binding`.  RFC 9266 updates RFC 5929
by adding this binding type as a replacement for the broken `tls-unique` type
in SASL mechanisms; it does **not** mandate `tls-exporter` for HTTP Negotiate.
No mainstream HTTP Negotiate client (Windows EPA/SSPI, browsers, or standard
curl builds) implements this type.  This option is provided for
experimentation only; do not use it in production.

### Client support

| Client | Supports channel bindings | Notes |
|--------|--------------------------|-------|
| curl ≥ 8.10.0, OpenSSL build | **Yes** (`server-end-point`) | See [curl PR #13098](https://github.com/curl/curl/pull/13098). Requires MIT Kerberos ≥ 1.19. Enabled by default. |
| curl, GnuTLS build | No | GnuTLS exposes no `tls-server-end-point` API. Debian/Ubuntu ship the GnuTLS build as the default `curl` package; the OpenSSL build is `curl-openssl` (Debian) or `curl` compiled from source. |
| Firefox on Linux | No | Uses [`GSS_C_NO_CHANNEL_BINDINGS`](https://bugzilla.mozilla.org/show_bug.cgi?id=563276) hard-coded in `nsAuthGSSAPI.cpp`; that bug has been open since 2010 with no scheduled fix. |
| Chrome/Chromium on Linux | No | [`http_auth_gssapi_posix.cc`](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/http_auth_gssapi_posix.cc) accepts a channel bindings argument but always passes `GSS_C_NO_CHANNEL_BINDINGS`. |
| Windows clients (IE, Edge, Chrome) | Yes (`server-end-point`) | Windows EPA sends channel bindings via SSPI automatically. |

Because Firefox and Chrome on Linux do not send channel bindings, setting
`auth_gss_channel_bindings server-end-point` will cause those browsers to
receive **403 Forbidden** instead of authenticating.  Restrict this directive
to deployments where all clients are known to support it (e.g. API endpoints
accessed only by curl or Windows browsers).

Troubleshooting
---------------

###
Check the logs.  If you see a mention of NTLM, your client is attempting to
connect using [NTLMSSP](http://en.wikipedia.org/wiki/NTLMSSP), which is
unsupported and insecure.

### Verify that you have an HTTP principal in your keytab ###

#### MIT Kerberos utilities ####

    $ KRB5_KTNAME=FILE:<path to your keytab> klist -k

or

    $ ktutil
    ktutil: read_kt <path to your keytab>
    ktutil: list

#### Heimdal Kerberos utilities ####

    $ ktutil -k <path to your keytab> list

### Obtain an HTTP principal

If you find that you do not have the HTTP service principal,
are running in an Active Directory environment,
and are bound to the domain such that Samba tools work properly

    $ env KRB5_KTNAME=FILE:<path to your keytab> net ads -P keytab add HTTP

If you are running in a different kerberos environment, you can likely run

    $ env KRB5_KTNAME=FILE:<path to your keytab> krb5_keytab HTTP

### Increase maximum allowed header size

In Active Directory environment, SPNEGO token in the Authorization header includes
PAC (Privilege Access Certificate) information, which includes all security groups
the user belongs to. This may cause the header to grow beyond default 8kB limit and
causes following error message:

    400 Bad Request
    Request Header Or Cookie Too Large

For performance reasons, best solution is to reduce the number of groups the user
belongs to. When this is impractical, you may also choose to increase the allowed
header size by explicitly setting the number and size of Nginx header buffers:

    large_client_header_buffers 8 32k;

Debugging
---------

The module prints all sort of debugging information if nginx is compiled with
the `--with-debug` option, and the `error_log` directive has a `debug` level.


NTLM
----

Note that the module does not support [NTLMSSP](http://en.wikipedia.org/wiki/NTLMSSP)
in Negotiate. NTLM, both v1 and v2, is an exploitable protocol and should be avoided
where possible.


Windows
-------

For Windows KDC/AD environments, see the documentation [here](README.Windows.md).


Help
----

If you're unable to figure things out, please feel free to open an
issue on Github and I'll do my best to help you.
