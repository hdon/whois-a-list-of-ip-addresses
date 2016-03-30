# whois-a-list-of-ip-addresses
Caching whois for a list of IP addresses

Have you ever wanted to whois a list of IP addresses?

With help from `whois(1)` this tool will do it, and cache the results. It looks
for CIDR blocks and IP address ranges and associates them with the cached record
to enable cached lookup.

Current limitations:

* Using `whois(1)` displaces me somewhat from the actual whois service.

* Only uses regexp search to identify CIDR blocks and IP address ranges, so it
  can get it wrong, like it does with 185.59.30.234

* No export functions as yet.

* Timestamp is stored with cached whois records, but there's no mechanism for
  them to expire.

* There's no way to export specific whois data yet, but it will dump the whole
  output of `whois(1)`

* If `whois(1)` outputs multiple sections with multiple IP address allocations
  listed, then for that address you have more than one level of information
  about the allocation. Any future address which falls into any of those levels
  but which may have more information about it available, will be seen as being
  cached. I hope this can be addressed in the future by lifting the hood of
  `whois(1)`

* Similarly, this tool can give you information not relevant to your IP address,
  simply because a previous address cached in the database falls into a higher
  level allocation mentioned in the output of `whois(1)`

# Links

https://www.apnic.net/about-APNIC/organization/history-of-apnic/history-of-the-regional-internet-registries

https://tools.ietf.org/html/rfc812

https://tools.ietf.org/html/rfc3912
