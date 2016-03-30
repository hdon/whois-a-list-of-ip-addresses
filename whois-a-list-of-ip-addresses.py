#!/usr/bin/env python
import popen2, sqlite3, os, sys, re, contextlib, itertools

def usage():
  print 'usage: %s <ipv4 address>|<filename of file containing newline-delimited IP addresses>' % sys.argv[0]
  raise SystemExit

if len(sys.argv) < 2:
  usage()
  
schema = '''
--CREATE TABLE ipv4_range (low, high, whois_id, unique(low, high));
CREATE TABLE ipv4_range (low, high, whois_id);
CREATE TABLE identity (name, unique(name));
CREATE TABLE whois (data, timestamp datetime default current_timestamp, query, unique(query, timestamp));
CREATE TABLE identity_ipv4_range (identity_id, ipv4_range_id, unique(identity_id, ipv4_range_id));
'''

db_filename = os.getenv('HOME') + '/.whois-ip.sqlite3'

if not os.path.isfile(db_filename):
  db = sqlite3.connect(db_filename)
  db.executescript(schema)
  db.close()

ipv4_re = re.compile(r'\b([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}\b)')
ipv4_range_re = re.compile(r'\b([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\s-\s([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\b')
# for cidr we need to support notation like 1.2.3.4/5 as well as 1.2/3
ipv4_cidr_re = re.compile(r'\b([0-9]{1,3})(\.([0-9]{1,3})(\.([0-9]{1,3})(\.([0-9]{1,3}))?)?)?/([0-9]{1,2})\b')

def re_searchall(expr, s):
  start = 0
  while start < len(s):
    match = expr.search(s, start)
    if not match:
      raise StopIteration
    start = match.end()
    yield match

def str_to_ipv4(s):
  global ipv4_re
  m = ipv4_re.match(s)
  return m and re_match_to_ipv4(m)

def re_match_to_ipv4(m, n=1):
  return (
    (int(m.group(n+0))<<24)
  | (int(m.group(n+1))<<16)
  | (int(m.group(n+2))<<8)
  |  int(m.group(n+3))
  )

def cidr_match_to_range_packed(m):
  a, b, c, d, nbits = (0 if m.group(n) is None else int(m.group(n)) for n in (1, 3, 5, 7, 8))
  if a & ~255 or b & ~255 or c & ~255 or d & ~255 or not nbits or nbits & ~31:
    return None
  # for cidr we need to support notation like 1.2.3.4/5 as well as 1.2/3

  network = (
    ((a) << 24 if a else 0) |
    ((b) << 16 if b else 0) | 
    ((c) <<  8 if c else 0) | 
    ( d        if d else 0)
  )
  mask = (1 << (32-nbits)) - 1
  assert network & mask == 0
  return network, network | mask

def whois_ipv4(who_ip):
  global db, ipv4_re, ipv4_range_re
  who_ip_packed = str_to_ipv4(who_ip)
  with contextlib.closing(db.cursor()) as cur:
    data = cur.execute('''
      select
        whois.data
      from ipv4_range
      join whois
        on whois.rowid = ipv4_range.whois_id
      where
        ipv4_range.low <= ?
        and ? <= ipv4_range.high
    ''', [who_ip_packed, who_ip_packed]).fetchone()

    if data:
      return data[0]

    whois_r, whois_e = popen2.popen2('whois %s' % who_ip, 0x10000, 'r')
    data = whois_r.read()

    cur.execute('insert into whois (data) values (?)', [unicode(data, 'ISO-8859-1')])
    whois_id = cur.lastrowid

    for match in re_searchall(ipv4_range_re, data):
      ip_low = re_match_to_ipv4(match, 1)
      ip_high = re_match_to_ipv4(match, 5)
      #cur.execute('insert into ipv4_range (low, high, whois_id) values (?, ?, ?) on conflict ignore', [ip_low, ip_high, whois_id])
      cur.execute('insert into ipv4_range (low, high, whois_id) values (?, ?, ?)', [ip_low, ip_high, whois_id])

    for match in re_searchall(ipv4_cidr_re, data):
      cidr = cidr_match_to_range_packed(match)
      if not cidr:
        continue
      ip_low, ip_high = cidr
      #cur.execute('insert into ipv4_range (low, high, whois_id) values (?, ?, ?) on conflict ignore', [ip_low, ip_high, whois_id])
      cur.execute('insert into ipv4_range (low, high, whois_id) values (?, ?, ?)', [ip_low, ip_high, whois_id])

    db.commit()
    return data

with sqlite3.connect(db_filename) as db:
  for arg in sys.argv[1:]:
    ip_arg = ipv4_re.match(arg)
    if ip_arg:
      print whois_ipv4(arg)
    else:
      with open(arg, 'r') as ip_list_file:
        for line in ip_list_file:
          line = line.rstrip()
          ip_line = ipv4_re.match(line)
          if ip_line:
            print whois_ipv4(line)
