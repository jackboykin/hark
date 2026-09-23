import asyncio, json, resource, sys, time
import dns.asyncquery, dns.message, dns.rcode, dns.flags, dns.exception, dns.rdatatype

names_path, rate, out_path, *ports = sys.argv[1:]
_, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
rate, ports = float(rate), [int(p) for p in ports]
names = [l.strip() for l in open(names_path) if l.strip()]

async def ask(port, name):
    q = dns.message.make_query(name, "A", want_dnssec=True, payload=1232)
    t = time.perf_counter()
    try:
        try:
            r = await dns.asyncquery.udp(q, "127.0.0.1", port=port, timeout=15, raise_on_truncation=True)
        except dns.message.Truncated:
            r = await dns.asyncquery.tcp(q, "127.0.0.1", port=port, timeout=15)
    except dns.exception.Timeout:
        return ["TIMEOUT", False, [], [], round((time.perf_counter() - t) * 1000)]
    except Exception as e:
        return [f"ERROR {type(e).__name__}", False, [], [], round((time.perf_counter() - t) * 1000)]
    ede = sorted(o.code for o in r.options if o.otype == 15)
    ans = sorted(f"{rr.name.to_text().lower()}|{dns.rdatatype.to_text(rr.rdtype)}|{rd.to_text().lower()}"
                 for rr in r.answer if rr.rdtype != dns.rdatatype.RRSIG for rd in rr)
    return [dns.rcode.to_text(r.rcode()), bool(r.flags & dns.flags.AD), ede, ans, round((time.perf_counter() - t) * 1000)]

async def main():
    out, done, t0 = open(out_path, "w"), 0, time.monotonic()
    async def one(name):
        nonlocal done
        r = await asyncio.gather(*(ask(p, name) for p in ports))
        out.write(json.dumps({"n": name, "r": r}) + "\n")
        done += 1
    tasks = set()
    for i, name in enumerate(names):
        await asyncio.sleep(max(0, t0 + i / rate - time.monotonic()))
        t = asyncio.create_task(one(name)); tasks.add(t); t.add_done_callback(tasks.discard)
        if i and i % 10000 == 0:
            print(f"{time.strftime('%X')} sent {i} done {done} in flight {len(tasks)}", file=sys.stderr, flush=True)
    await asyncio.gather(*tasks)
    out.close()

asyncio.run(main())
