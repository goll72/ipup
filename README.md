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

These should be easily installable using your system's package manager.

## Actually building

Simply clone the repository and run

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

```
[wlan0]
server = example.com
# default
port = 53

key-name = example
key-secret = ...
# or, alternatively:
key-file = /etc/ipup/key
key-algo = HMAC-SHA512

zone = example.com
record = foo
record-type = A/AAAA

# delete existing record(s), default: no
delete-existing = yes

# verify system is reachable through a given
# address before adding it, default: no
verify-reachable = yes

# verify duplicate addresses, useful for spurious
# events due to misconfigured DHCP, default: yes
verify-duplicate = yes
```

# Running

Specify a configuration file with the `-c` option, otherwise it will
look for a configuration file in:

 * `/etc/ipup/conf`
 * `$XDG_CONFIG_HOME/ipup/conf`
 * `~/.ipup.conf`
