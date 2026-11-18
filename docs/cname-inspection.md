# CNAME inspection

`egress-guard cname-check HOST` asks the macOS system resolver about one fully
qualified hostname. The report shows the current host policy for the requested
name and for each reachable canonical alias. A new alias can lead to a domain
already in the tracker or threat feeds even when the original name is absent
from the static alias list. The report keeps each name's policy result
independent, including temporary tracker exceptions, tracker pause, and threat
and local block precedence. Running the check leaves live filtering unchanged.

The command asks for A and AAAA records and reads the intermediate CNAME records
returned by DNS-SD. The resolver worker has a three-second timeout, and the
command inspects at most 32 records and 12 hops per address family. It reports
the canonical owner name of a terminal address record and omits the address.
A negative DNS reply can complete
a family observation without providing a terminal. Timeouts, incomplete chains,
conflicting answers, and unavailable policy snapshots leave the report
indeterminate. A match anywhere in the report only describes how the current
rules classify that individual name.

Contacts are limited to the configured system resolver path, which can serve
a cached answer or query its existing upstream. macOS may send `.local`
lookups to the local network using multicast DNS. Egress Guard adds no fallback
resolver or DNS settings, activity records, or cache. The operating system
and its configured resolvers follow their own caching and retention policies.
Use ASCII Punycode labels for international names whose Unicode spelling
cannot be round-tripped by Python's standard IDNA codec.

The report captures the first terminal response for each family and includes
records already queued with it. Later replies or network changes may produce
different results. Apple may report an original TTL even if the system cache
supplies the answer. The check cannot establish which
resolver an application with its own DNS used, or whether a later connection
uses the same answer. IPv4 and IPv6 can differ. Split DNS can depend on the
active network and VPN resolver configuration. A check on a public hostname
does not validate private-domain routing. A DNS answer also cannot distinguish
URLs served on the same hostname.

- [Apple DNSServiceQueryRecord API](https://developer.apple.com/documentation/dnssd/dnsservicequeryrecord(_:_:_:_:_:_:_:_:))
- [mDNSResponder DNS-SD API flags and callback contract](https://github.com/apple-oss-distributions/mDNSResponder/blob/main/mDNSShared/dns_sd.h)
- [mDNSResponder DNS-SD record serialization](https://github.com/apple-oss-distributions/mDNSResponder/blob/main/mDNSShared/uds_daemon.c)
- [mDNSResponder system resolver and multicast DNS](https://github.com/apple-oss-distributions/mDNSResponder)
- [Apple split DNS match domains](https://developer.apple.com/documentation/networkextension/nednssettings/matchdomains)
- [Longitudinal study of CNAME tracking](https://arxiv.org/abs/2102.09301)
