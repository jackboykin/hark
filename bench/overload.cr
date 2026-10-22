# overload <overload.sh OUT dir>: one row per run, pass/fail per criterion.
#
#   loss  probe loses nothing up to 4x the ceiling
#   p99   probe p99 <= P99_MS (7: 5 ms plus 2 ms slack) at every level
#   good  miss goodput >= 0.95x the ceiling at every level
#   acct  hark's unanswered (dropped + shed + late + reaped) plus kernel drops
#         on the listener and the generators equals offered - answered within 0.1%
#   unsat the core was under 97% busy: at 1x and above the load did not reach
#         hark, so the run proves nothing
# A ceiling measured on an unsaturated core invalidates the whole series.
module Overload
  def self.num(key, text)
    text[/#{key}:\s+(\d+)/, 1]?.try(&.to_i64) || 0_i64
  end

  def self.unsent(dump)
    dump.scan(/stats clients\.unanswered\.\w+\s+(\d+)/).sum(0_i64) { |m| m[1].to_i64 }
  end

  def self.main(args)
    dir = args[0]
    p99_ms = ENV.fetch("P99_MS", "7").to_f
    meta = File.read("#{dir}/meta").split.to_h { |kv| k, v = kv.split('='); {k, v} }
    ceiling, length = meta["ceiling"].to_f, meta["len"].to_f
    cbusy = File.read("#{dir}/ceiling")[/busy ([\d.]+)/, 1]?.try(&.to_f) || 0.0
    abort "INVALID: the miss ceiling (#{"%.0f" % ceiling} qps) was measured at #{"%.1f" % cbusy}% core busy" if cbusy < 97
    puts "miss ceiling #{"%.0f" % ceiling} qps (closed loop, #{"%.1f" % cbusy}% busy), #{"%.0f" % length} s per run"
    puts "lvl run  offered  goodput g/ceil   probe  p50ms  p99ms  rxq KB  k.drops  unsent   acct  busy  verdict"
    fails = runs = 0
    Dir.glob("#{dir}/*.probe").sort_by { |f| File.basename(f).split('.').first(2).map(&.to_i) }.each do |f|
      b = f.rchop(".probe")
      level, run = File.basename(b).split('.').map(&.to_i)
      floods = Dir.glob("#{b}.flood*").sort.map { |x| File.read(x) }
      sent, done = floods.sum { |t| num("Queries sent", t) }, floods.sum { |t| num("Queries completed", t) }
      # responses/s during the constant phase, summed over instances
      good = Dir.glob("#{b}.plot*").sort.sum do |p|
        v = File.read_lines(p).reject(&.starts_with?('#')).map(&.split).select { |l| l[0].to_f < length }.map { |l| l[3].to_f }
        v.empty? ? 0.0 : v.mean
      end
      probe = File.read(f)
      psent, pdone = num("Queries sent", probe), num("Queries completed", probe)
      lat = probe.scan(/^> \w+ \S+ \S+ ([\d.]+)/m).map { |m| m[1].to_f * 1e3 }.sort
      pc = ->(q : Float64) { lat.empty? ? Float64::NAN : lat[Math.min(lat.size - 1, (lat.size * q).to_i)] }
      rxq, ldrop, gdrop = File.read("#{b}.udp").split.map(&.to_i64)
      hark = unsent(File.read("#{b}.stats1")) - unsent(File.read("#{b}.stats0"))
      offered, answered = sent + psent, done + pdone
      acct = (hark + ldrop + gdrop - (offered - answered)).abs / offered
      busy = File.read("#{b}.busy").split[0].to_f
      loss = (psent - pdone) / psent
      bad = {
        "loss"  => level > 4 || pdone == psent,
        "p99"   => pc.call(0.99) <= p99_ms,
        "good"  => good >= 0.95 * ceiling,
        "acct"  => acct <= 0.001,
        "unsat" => busy >= 97,
      }.reject { |_, ok| ok }.keys
      short = sent < 0.97 * ceiling * level * length
      runs += 1
      fails += 1 unless bad.empty?
      puts "%2dx %3d %7.0fk %7.1fk %6.3f  %5.1f%% %6.2f %6.2f  %6.0f %8d %7d %5.2f%% %5.1f  %s%s" % {
        level, run, sent / length / 1e3, good / 1e3, good / ceiling, 100 * loss, pc.call(0.5), pc.call(0.99),
        rxq / 1024, ldrop + gdrop, hark, 100 * acct, busy, bad.empty? ? "pass" : "FAIL #{bad.join(',')}", short ? "  (short)" : "",
      }
    end
    puts "#{fails > 0 ? "FAIL" : "PASS"}: #{runs - fails}/#{runs} runs pass"
  end
end
