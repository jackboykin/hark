import sys, json, time, concurrent.futures as cf
import dns.message, dns.query, dns.flags, dns.rcode
port, names, threads = int(sys.argv[1]), [l.strip() for l in open(sys.argv[2]) if l.strip()], int(sys.argv[3])
def one(n):
    q = dns.message.make_query(n, 'A', want_dnssec=True)
    t = time.perf_counter()
    try:
        r = dns.query.udp(q, '127.0.0.1', port=port, timeout=10)
        return n, (time.perf_counter()-t)*1000, dns.rcode.to_text(r.rcode()), bool(r.flags & dns.flags.AD)
    except Exception as e:
        return n, (time.perf_counter()-t)*1000, 'TIMEOUT', False
with cf.ThreadPoolExecutor(threads) as ex:
    print(json.dumps(list(ex.map(one, names))))
