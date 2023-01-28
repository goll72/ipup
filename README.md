ipup
====

Small tool that uses Netlink to detect IP address changes
on specified interfaces and update a DNS entry using RFC 2136.

# Building

## Dependencies

 * meson
 * libldns
 * libinih
 * libnl
 * libcriterion (testing only)

These should be easily installable using your system's package manager.
Note that on some distributions you may have to install libnl and
libnl-route separately.

## Actually building

Simply clone the repository:

```
$ git clone https://github.com/goll72/ipup
```

and run

```
$ meson setup build
$ meson compile -C build
```

To install, run

```
$ meson install -C build
```

# Configuration

Ipup's configuration file uses a syntax similar to INI. For instance:

```ini
[server/example]
fqdn = example.com
# default
port = 53

key-name = example
key-secret = ...
# or, alternatively:
key-file = /etc/ipup/key
key-algo = HMAC-SHA512

max-retry = 10

[iface/wlan0]
server = example
zone = example.com
record = foo

# default: no
delete-existing = yes

# mutually exclusive
ttl = 86400s
# default: no
respect-ttl = yes
```

 - There are two types of sections. Those starting with `server/` denote a DNS server,
    that may be reused. Those starting with `iface/` denote network interfaces.
 - Boolen options can take a value of `yes`, `true`, `1` or `no`, `false` and `0`.
 - If the record isn't a valid subdomain of the zone, it will be concatenated with it.
 - Time durations can take the following specifiers: `s`econds, `m`inutes, `h`ours or `d`ays.
    Multiple specifiers are allowed, e.g. `1d 2h 10m`.

## Options

### For the server

 - `fqdn` is the FQDN (fully qualified domain name) of the DNS server.
 - `port` is the port used for the DNS connection (53 by default).
 - `key-secret` is the Base64-encoded key secret.
 - `key-file` is a file containing only the Base64-encoded key secret.
 - `key-algo` is the encryption algorithm used. Possible values can be listed with
    `ldns-keygen -a list`.
 - `max-retry` sets the maximum number of times ipup will retry to send
    a request to the server before giving up.

### For the interface

 - `server` is the name of the server used for the given interface as specified in its
    section (not the FQDN).
 - `ttl` specifies the TTL to be used for the records. The default TTL used if
    it isn't specified, and neither is `respect-ttl`, is 1 hour.
 - `respect-ttl` makes the TTL of the DNS record match the TTL of the given
    address (valid lifetime). You should only enable it if you know your leases are
    consistently short enough.
 - `delete-existing` will delete any DNS records not present in the kernel
    address table on startup.

### For either

These options can be placed in either the server or the interface section,
but they must be fully specified in only one or the other.

 - `zone` is the DNS zone for the record.
 - `record` is the DNS record that will be updated.

# Running

Specify a configuration file with the `-c` option, otherwise it will
look for a configuration file in:

 * `/etc/ipup/conf`
 * `$XDG_CONFIG_HOME/ipup/conf`
 * `~/.ipup.conf`

# Notes

Only IPv6 is supported, as IPv4 needs an external host to be able to tell your
public IPv4 address. That much is manageable, however, polling for address
changes is not. Methods such as assuming IPv4 leases expire alongside IPv6
leases on dual-stack systems could work, I'm not sure.
