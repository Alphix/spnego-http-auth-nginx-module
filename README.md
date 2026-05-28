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
and pass an `--add-module` option to nginx configure to build the module into
the nginx binary:

    ./configure --add-module=spnego-http-auth-nginx-module

Alternatively, pass `--add-dynamic-module` to build it as a loadable module
(`ngx_http_auth_spnego_module.so`), which is then enabled with a
`load_module` directive in `nginx.conf`:

    ./configure --add-dynamic-module=spnego-http-auth-nginx-module

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

Internal Redirects
------------------

Users stay authenticated when nginx passes a request on to another location
internally (for example with `index`, `try_files`, `error_page` or a named
location), as long as that location uses the same `auth_gss` settings.  Its
`auth_gss_authorized_principal` list still applies.  If the settings differ,
the user gets a 401: with basic authentication fallback enabled, the browser
prompts for a username and password.

Credential Delegation
---------------------

The `auth_gss_delegation` directive controls whether and how nginx handles
delegated Kerberos credentials.  It accepts four values:

* `off` (default): credentials are neither captured nor used.
* `unconstrained`: capture the client's forwarded TGT when the client sets
  the `GSS_C_DELEG_FLAG` in its SPNEGO token (i.e. the client opts in to
  delegation).  The credential is stored as a FILE ccache under
  `auth_gss_deleg_ccache_dir`, named after the authenticated principal and
  overwritten on each successful delegation, and exposed via the
  `$krb5_cc_name` nginx variable.  It can also be passed to a backend
  in-memory via the `$krb5_cred_exported` nginx variable, which
  base64-encodes the credential on demand using `gss_export_cred()` without
  exposing the ccache path.
* `constrained`: perform S4U2Proxy (constrained delegation).  The service
  principal's TGT is held in a per-worker in-memory ccache (see the Service
  Ccache section below) and used to obtain a service ticket impersonating
  the authenticated user.
* `both`: perform both unconstrained and constrained delegation.

Example — unconstrained delegation, passing the ccache path to a FastCGI backend:

    auth_gss_delegation unconstrained;
    fastcgi_param KRB5CCNAME $krb5_cc_name;

Example — unconstrained delegation, passing the credential blob in-memory:

    auth_gss_delegation unconstrained;
    fastcgi_param KRB5_EXPORTED_CRED $krb5_exported_cred;

Example — constrained delegation (S4U2Proxy):

    auth_gss_delegation constrained;
    fastcgi_param KRB5CCNAME $krb5_cc_name;

Constrained delegation requires a GSSAPI library that supports
`gss_acquire_cred_from()` and `gss_store_cred_into()` (MIT Kerberos; planned
for Heimdal 8).

Files under `auth_gss_deleg_ccache_dir` are not removed by the module, so
install `contrib/nginx-tmpfiles.conf` to `/etc/tmpfiles.d/` to have
`systemd-tmpfiles` periodically delete ccache files for principals that
haven't re-authenticated recently. The example file's `1d` age is a
starting point; tune it to your deployment.


Service Credential Cache
------------------------

The HTTP service principal's TGT for S4U2Proxy is held in a per-worker
in-memory (MEMORY) ccache.  No file is ever written.

Each nginx worker maintains one MEMORY ccache per service principal.  Because
MEMORY ccaches are per-process (not shared between workers), each worker
independently checks its own ccache and fetches a new TGT from the keytab when
needed.  When a TGT expires all N workers each make one independent TGS-REQ
rather than one worker doing it for all.  For typical TGT lifetimes (24 h) and
worker counts (4–16), this is negligible.

**Security properties.**

* The TGT never appears on disk; there is no file to read or steal.
* No predictable filename for an attacker to target.
* The TGT vanishes automatically when a worker exits — no orphaned files.
* Per-worker isolation: a memory-disclosure exploit affecting one worker does
  not expose the TGT of any other worker.
* If nginx worker processes generate core dumps (disabled by default via
  `setrlimit(RLIMIT_CORE, 0)`) the TGT would be present in the dump.
* On nginx restart or graceful reload every worker must fetch a fresh TGT from
  the KDC.  With file-based ccaches a valid TGT can survive a restart.


Security Considerations for $krb5_exported_cred
------------------------------------------------

**Debug logging.**  When nginx is compiled with `--with-debug` and
`error_log ... debug` is active, nginx logs FastCGI parameters at debug level.
This includes `KRB5_EXPORTED_CRED`, which contains a live, base64-encoded Kerberos
credential blob.  Anyone with access to the error log can extract and use it.
**Do not enable debug-level logging in production when using this variable.**

**Backend transport.**  The credential blob travels over the FastCGI/uwsgi/SCGI
connection between nginx and the backend.  Use a Unix socket for this
connection.  A cleartext TCP socket — even on loopback — allows any process on
the host with sufficient privilege (e.g. packet capture) to intercept the
credential.

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
* `auth_gss_realm`: Kerberos realm name.  Basic authentication fallback
  requires either this to be set or a `default_realm` to be configured in
  `krb5.conf` (the latter being the recommended approach). If this is specified,
  the realm is only passed to the nginx variable `$remote_user` if it differs
  from this default.  To override this behavior, set `auth_gss_format_full` to
  `on` in your configuration.
* `auth_gss_force_realm`: Forcibly authenticate using the realm configured in
  `auth_gss_realm` or the system default realm if `auth_gss_realm` is not set.
  This will rewrite `$remote_user` if the client provided a different realm.  If
  `auth_gss_format_full` is not enabled, `$remote_user` will not include a realm
  even if one was specified by the client.
* The nginx core [`auth_delay`](https://nginx.org/en/docs/http/ngx_http_core_module.html#auth_delay)
  directive is honored when an incorrect username/password is provided.


Optional Authentication
-----------------------

The SPNEGO protocol always begins with a 401 challenge from the server.
Clients that lack Kerberos support, or choose not to authenticate, will
stop at that 401 and never make a second request.  The nginx
[`error_page`](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page)
directive can be used to serve meaningful content on that 401 response —
for instance, a login form provided by the same backend that handles
authenticated requests.  The backend receives the request with
`$remote_user` unset and can present a login form accordingly.

    location /app.php {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        auth_gss on;
        # ... other auth_gss directives ...
        error_page 401 @unauthenticated;
    }

    location @unauthenticated {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$uri;
    }

Placing `error_page 401 @unauthenticated` in the `server` block rather
than in individual `location` blocks causes it to apply to all locations
that do not override it.


Channel Bindings
----------------

The `auth_gss_channel_binding` directive binds a Kerberos authentication
exchange to the TLS session it travels over, preventing a man-in-the-middle
attack where a valid Negotiate token is relayed to a different server. The
directive requires TLS; configuring it on a plain HTTP connection will cause
authentication to fail.

    auth_gss_channel_binding off;              # default – existing behaviour
    auth_gss_channel_binding server-end-point; # RFC 5929 – hash of server cert
    auth_gss_channel_binding exporter;         # RFC 9266 – TLS keying material (tech demo)

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

Because Firefox and Chrome on Linux do not support channel bindings, setting
`auth_gss_channel_binding server-end-point` will cause those browsers to fail.
Restrict this directive to deployments where all clients are known to have
proper support for channel bindings.


Nginx Variables
---------------

The following variables are set by this module:

* `$krb5_auth_type`: how the current request was authenticated.  Values:
  `spnego` (Kerberos/SPNEGO negotiate), `basic` (HTTP Basic auth), or
  `cookie` (session cookie).  Empty for unauthenticated requests.
* `$krb5_cc_name`: path to the delegated credential ccache (see Credential
  Delegation).
* `$krb5_exported_cred`: base64-encoded exported credential blob (see
  Credential Delegation and Security Considerations for $krb5_exported_cred).
* `$krb5_session_principal`: the authenticated principal for
  cookie-authenticated requests (see Session Cookie).


Session Cookie
--------------

On deployments behind a load balancer every request would normally require a
full SPNEGO round-trip.  The session cookie feature avoids this: after the
first successful authentication nginx issues an AES-256-GCM encrypted cookie,
and subsequent requests from any cluster node are authenticated using the cookie
alone, without a SPNEGO handshake.

To enable, configure a 32-byte key (64 hex digits) shared across all cluster
nodes and a non-zero expiry:

    auth_gss_session_key 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20;
    auth_gss_session_expiry 3600;  # seconds; 0 = disabled

Alternatively, load the key from a file (one 64-hex-char line):

    auth_gss_session_key_file /etc/nginx/session.key;
    auth_gss_session_expiry 3600;

The actual cookie expiry is `min(auth_gss_session_expiry, remaining Kerberos ticket lifetime)`.

`auth_gss_service_name` must also be set. It is baked into each cookie's
authenticated associated data, binding the cookie to this specific service so
that it cannot be replayed against another service that happens to share the
same `auth_gss_session_key`. nginx refuses to start if
`auth_gss_session_key`/`auth_gss_session_key_file` is set without
`auth_gss_service_name`.

Optional directives:

* `auth_gss_session_cookie_name`: name of the cookie (default: `gss_session`).
* `auth_gss_session_cookie_attrs`: Set-Cookie attributes appended after
  `Max-Age` (default: `HttpOnly; Path=/; Secure; SameSite=Lax`).
  Override this when nginx is behind a TLS-terminating load balancer and the
  direct connection is plain HTTP — in that case the browser will never see
  HTTPS and the `Secure` flag should be dropped or managed differently:

      auth_gss_session_cookie_attrs "HttpOnly; Path=/; SameSite=Lax";

The authenticated principal for cookie-authenticated requests is exposed as
`$krb5_session_principal`.

Session cookies require nginx to be built with `--with-http_ssl_module`
(for OpenSSL AES-256-GCM support); the session directives are unavailable
and ignored otherwise.

### Security Considerations

Session cookies are deliberately portable: the same cookie is accepted on
any cluster node, over any connection, until `auth_gss_session_expiry`
elapses. This has consequences worth understanding before enabling the
feature:

* **Bearer token.** Anyone who obtains a valid cookie value can use it until
  it expires or the session key is rotated — there is no per-request proof
  of possession (Basic-derived cookies are the exception: they also re-check
  the client's password on every request). Treat the cookie value with the
  same care as a short-lived password, and keep `HttpOnly` and `Secure` in
  `auth_gss_session_cookie_attrs` unless you have a specific reason to drop
  them.

* **`Secure` only constrains browsers.** A party that already has the cookie
  value (e.g. via XSS, or a compromised log) can replay it directly to a
  plain-HTTP listener with a tool like curl, regardless of the `Secure`
  attribute. If nginx terminates TLS itself, there is no plain-HTTP listener
  to replay against. If nginx is a backend behind a TLS-terminating load
  balancer (and therefore necessarily listens on plain HTTP towards the
  balancer), make sure that listener is reachable only from the balancer —
  the same network hygiene already required for trusting `X-Forwarded-For`
  and similar headers.

* **`auth_gss_channel_binding` does not extend to the cookie.** Channel
  binding proves that a *specific SPNEGO handshake* happened over a
  *specific TLS connection*. A session cookie minted from that handshake is,
  by design, usable on any later connection, on any cluster node — that is
  what makes it useful as a session cookie, but it also means the
  channel-binding guarantee covers only the initial handshake, not the
  lifetime of the session. If a location requires channel binding to hold
  for the entire session, do not enable session cookies on it, or set a
  short `auth_gss_session_expiry` to bound the window during which this
  matters.

Authorization
-------------

This module handles authentication (verifying who the user is) but does not
provide authorization (deciding what the user is allowed to do).
Authorization must be configured separately, for example using nginx's
built-in `auth_request` directive, `access_by_lua_file`, or an external
access-control system.

An example Lua script that checks LDAP group membership after SPNEGO
authentication is provided in `contrib/ldap_authz.lua`.  It requires
`lua-resty-ldap` and the nginx Lua module.  To use it:

    cp contrib/ldap_authz.lua /etc/nginx/lua/ldap_authz.lua

Edit the configuration variables at the top of the script, then reference
it from your nginx location block:

    location /protected {
        auth_gss on;
        auth_gss_format_full on;
        access_by_lua_file /etc/nginx/lua/ldap_authz.lua;
    }



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


Important Changes
-----------------

### v1.1.4

* `$krb5_exported_cred`: new nginx variable to pass delegated Kerberos credentials in-memory to backends without writing a ccache file.
* Constrained delegation service TGT is now held in a per-worker in-memory ccache; the `auth_gss_service_ccache` file-based directive has been removed.
* **Breaking change**: `auth_gss_delegate_credentials` and `auth_gss_constrained_delegation` replaced by `auth_gss_delegation` accepting `off`, `unconstrained`, `constrained`, or `both`.
* New `auth_gss_deleg_ccache_dir` directive stores delegated credentials as named FILE ccaches; the ccache path is exposed via `$krb5_cc_name`.
* Session cookie support: new `auth_gss_session_key`, `auth_gss_session_expiry`, and related directives; `$krb5_session_principal` variable for cookie-authenticated requests.


Help
----

If you're unable to figure things out, please feel free to open an
issue on Github and I'll do my best to help you.
