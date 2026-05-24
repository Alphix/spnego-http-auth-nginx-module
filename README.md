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

| Directive | Valid values | Default | Description |
|-----------|-------------|---------|-------------|
| `auth_gss` | `on`/`off` | `off` | Enable or disable SPNEGO authentication for a location. |
| `auth_gss_keytab` | file path | `/etc/krb5.keytab` | Absolute path to the keytab file containing the HTTP service credentials. |
| `auth_gss_service_name` | string | (hostname-based) | Service principal name (e.g. `HTTP/webserver01.example.com`). Required when accessed via a CNAME. |
| `auth_gss_allow_basic_fallback` | `on`/`off` | `off` | Accept HTTP Basic credentials when the client does not attempt SPNEGO. See security warning in the text below. |
| `auth_gss_realm` | string | (unset) | Kerberos realm. Normally not needed — the realm is negotiated automatically. |
| `auth_gss_authorized_principal` | string | (unset) | Allowlist a specific principal (e.g. `alice@EXAMPLE.COM`). Multiple directives are supported. |
| `auth_gss_authorized_principal_regex` | regex | (unset) | Allowlist principals matching a regex (e.g. `^.*/admin@EXAMPLE\.COM$`). Multiple directives are supported. |
| `auth_gss_format_full` | `on`/`off` | `off` | Include `@realm` in `$remote_user` even when the realm matches `auth_gss_realm`. |
| `auth_gss_force_realm` | `on`/`off` | `off` | Force authentication against the configured realm, rewriting any client-supplied realm. |
| `auth_gss_map_to_local` | `on`/`off` | `off` | Map the Kerberos principal to a local username via `gss_localname()`. |
| `auth_gss_delegate_credentials` | `off`/`on`/`export` | `off` | Delegate user credentials: `on` writes a per-request ccache file (`$krb5_cc_name`); `export` passes credentials in-memory as `$krb5_cred_exported`. |
| `auth_gss_constrained_delegation` | `on`/`off` | `off` | Enable S4U2Proxy constrained delegation. Requires `auth_gss_delegate_credentials`. |
| `auth_gss_channel_bindings` | `off`/`server-end-point`/`exporter` | `off` | Bind the Kerberos exchange to the TLS session. `server-end-point` (RFC 5929) is the only production-ready choice. |

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
The service principal's TGT is held in a per-worker in-memory ccache (see the
Service Ccache section below).

**Credential forwarding** (`on`):

    auth_gss_delegate_credentials on;
    auth_gss_constrained_delegation on;
    fastcgi_param KRB5CCNAME $krb5_cc_name;

The delegated credentials are written to a temporary ccache file and destroyed
once the request completes.

**Export mode** (`export`):

    auth_gss_delegate_credentials export;
    auth_gss_constrained_delegation on;
    fastcgi_param KRB5_CRED_EXPORTED $krb5_cred_exported;

No per-request file is created.  The credential blob is passed directly to the
FastCGI backend as a base64-encoded parameter.  See the Security Considerations
section below before using this mode.

Constrained delegation is currently only supported using the Negotiate authentication
scheme and has only been tested with MIT Kerberos (use at your own risk with Heimdal).

Service Ccache
--------------

The HTTP service principal's TGT for S4U2Proxy is held in a per-worker
in-memory (MEMORY) ccache.  No file is ever written.

**Implementation.**  Each nginx worker maintains one MEMORY ccache per service
principal, named `MEMORY:nginx_svc_<principal>` (e.g.
`MEMORY:nginx_svc_HTTP/server.example.com@EXAMPLE.COM`).  MIT Kerberos MEMORY
ccaches are identified by an arbitrary string; `/`, `@`, and `.` are valid in
the name.  Naming after the principal ensures that a worker handling multiple
locations with different service principals gets one independent MEMORY ccache
per principal with no interference between them.

Each worker independently checks its own ccache and fetches a new TGT from the
keytab when needed.  When a TGT expires all N workers each make one independent
TGS-REQ rather than one worker doing it for all.  For typical TGT lifetimes
(24 h) and worker counts (4–16), this is negligible.

**Security properties.**

* The TGT never appears on disk; there is no file to read or steal.
* No predictable filename for an attacker to target.
* The TGT vanishes automatically when a worker exits — no orphaned files.
* Per-worker isolation: a memory-disclosure exploit affecting one worker does
  not expose the TGT of any other worker.
* If nginx worker processes generate core dumps (disabled by default via
  `setrlimit(RLIMIT_CORE, 0)`) the TGT would be present in the dump.
* On nginx restart or graceful reload every worker must fetch a fresh TGT from
  the KDC.  If the KDC is unreachable at restart time, S4U2Proxy will fail
  until connectivity is restored.  This is an availability consideration, not
  a security one.

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

Basic authentication fallback is **disabled by default**.  When enabled, the
module falls back to accepting plain Kerberos username/password credentials if
the client does not attempt SPNEGO negotiation.

> **Security warning:** enabling basic fallback causes nginx to contact the KDC
> with the user's password on every unauthenticated request.  This exposes the
> KDC to password-spray attacks, can trigger account lockouts, and relies on
> transport-layer encryption to protect the password in transit.  Only enable
> it if you fully understand these risks and have TLS in place end-to-end.

To enable it explicitly:

    auth_gss_allow_basic_fallback on

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
from relaying a valid Negotiate token to a different server. The directive
requires TLS; configuring it on a plain HTTP connection will cause
authentication to fail.

    auth_gss_channel_bindings off;              # default – existing behaviour
    auth_gss_channel_bindings server-end-point; # RFC 5929 – hash of server cert
    auth_gss_channel_bindings exporter;         # RFC 9266 – TLS keying material (tech demo)

**`server-end-point`** ([RFC5929](https://www.rfc-editor.org/rfc/rfc5929.html))
hashes the server's TLS certificate. This is the only type supported by
mainstream clients (see the table below).

**`exporter`** ([RFC9266](https://www.rfc-editor.org/rfc/rfc9266.html)) derives
32 bytes from the TLS keying material. This type is provided for
experimentation only; do not use it in production.

### Client support

| Client          | Support | Notes |
|-----------------|---------|-------|
| curl            | **Yes** | curl ≥ 8.10.0 with OpenSSL (see [curl PR #13098](https://github.com/curl/curl/pull/13098)) and MIT Kerberos ≥ 1.19. |
| Firefox (Linux) | **No**  | See [Mozilla bug #563276](https://bugzilla.mozilla.org/show_bug.cgi?id=563276) |
| Chrome (Linux)  | **No**  | See the reference to `GSS_C_NO_CHANNEL_BINDINGS` in [the source](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/http/http_auth_gssapi_posix.cc). |
| Windows clients | **Yes** | IE, Edge, Chrome, Firefox, etc support this automatically via [SSPI](https://en.wikipedia.org/wiki/Security_Support_Provider_Interface). |

Because Firefox and Chrome on Linux do not send channel bindings, setting
`auth_gss_channel_bindings server-end-point` will cause those browsers to fail.
Restrict this directive to deployments where all clients are known to have
proper support for channel bindings.


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
