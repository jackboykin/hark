# an <tp.sh output> [side...]: each side, then each against the first.
#
# One layout a side: the per-round ratio, its median with a bootstrap 95% CI,
# and a sign test, for qps and for each PERF=1 counter per query. Several
# (layouts.sh): the difference of per-layout means, bootstrapped over
# layouts, real only if the CI excludes 0 and |Δ| > 1%, the reach of a
# relink.
require "./stats"

module An
  record Run, round : String, side : String, lay : String, qps : Float64, lost : Int64,
    busy : Float64, lat : Array(Float64?), ev : Hash(String, Float64)

  BOOT = 20000

  def self.digits?(s)
    !s.empty? && s.each_char.all?(&.ascii_number?)
  end

  def self.parse(line) : Run?
    p = line.split
    return unless p.size >= 10 && digits?(p[0])
    kv = p[10..].select(&.includes?('=')).to_h { |f| k, v = f.split('=', 2); {k, v} }
    num = ->(k : String) { (v = kv[k]?) && digits?(v.sub('.', "")) ? v.to_f : nil }
    done = p[4].to_i64
    ev = {} of String => Float64
    (kv.keys - %w[cpu p50 p99 p999]).each do |k|
      n = num.call(k)
      ev[k] = n / done if n && n != 0 && done != 0
    end
    Run.new(p[0], p[1], p[2], p[3].to_f, p[5].to_i64, p[6].to_f, %w[p50 p99 p999].map { |k| num.call(k) }, ev)
  end

  def self.cv(v : Array(Float64))
    v.size > 1 ? 100 * v.stdev / v.mean : 0.0
  end

  def self.pct(x)
    "%+.2f%%" % (100 * (x - 1))
  end

  def self.choose(n, k)
    (1..k).reduce(1.0) { |c, i| c * (n - k + i) / i }
  end

  def self.main(args)
    path, sides = args[0], args[1..]
    runs = File.read_lines(path).compact_map { |l| parse(l) }
    sides = runs.map(&.side).uniq if sides.empty?
    by = runs.group_by(&.side)
    rng = Random::PCG32.new(1)
    resample = ->(v : Array(Float64)) { Array.new(v.size) { v.sample(rng) } }
    ci = ->(draw : -> Float64) do
      boot = Array.new(BOOT) { draw.call }.sort
      {boot[BOOT // 40], boot[BOOT - BOOT // 40]}
    end

    puts File.basename(path)
    w = sides.max_of(&.size)
    sides.each do |s|
      rs = by[s]
      q = rs.map(&.qps)
      lat = (0..2).map { |i| rs.map(&.lat[i]) }.reject(&.includes?(nil)).map { |v| v.compact.median }
      unsat = rs.count { |r| r.busy < 97 }
      line = "  #{s.rjust(w)} median #{"%9.0f" % q.median} qps  cv #{"%.2f" % cv(q)}%  range #{"%.0f" % q.min}-#{"%.0f" % q.max}" \
             "  #{"%.3f" % (1e6 / q.median)} µs/query  busy min #{"%.1f" % rs.min_of(&.busy)}%  lost #{rs.sum(&.lost)}"
      line += "  p50 %.0f p99 %.0f p99.9 %.0f µs" % {lat[0], lat[1], lat[2]} unless lat.empty?
      line += "  UNSATURATED #{unsat}/#{q.size} runs <97% busy" if unsat > 0 && lat.empty?
      puts line
      unless rs[0].ev.empty?
        puts "  #{"".rjust(w)} per query: " + rs[0].ev.keys.join("  ") { |k|
          v = rs.map(&.ev[k])
          "#{k} #{"%.0f" % v.median} cv #{"%.2f" % cv(v)}%"
        }
      end
    end

    a = sides[0]
    sides[1..].each do |b|
      lays = {a, b}.to_h { |s| {s, by[s].group_by(&.lay).transform_values(&.map(&.qps))} }
      if lays.values.max_of(&.size) > 1
        mean = lays.transform_values(&.values.map(&.mean))
        {a, b}.each do |s|
          puts "  #{s.rjust(w)} #{mean[s].size} layouts, means #{mean[s].sort.join(' ') { |m| "%.0f" % m }}  cv #{"%.2f" % cv(mean[s])}%"
        end
        d = mean[b].mean / mean[a].mean
        lo, hi = ci.call(-> { resample.call(mean[b]).mean / resample.call(mean[a]).mean })
        real = (lo > 1 || hi < 1) && (d - 1).abs > 0.01
        puts "  layouts #{b}/#{a} #{pct(d)}  95% CI [#{pct(lo)}, #{pct(hi)}]  #{real ? "REAL" : "within layout noise"}"
        next
      end
      rounds = runs.group_by(&.round).values.map(&.to_h { |r| {r.side, r} })
      measures = [{"qps", ->(r : Run) { r.qps }}] + by[a][0].ev.keys.map { |k| {k, ->(r : Run) { r.ev[k] }} }
      measures.each do |name, f|
        ratio = rounds.select { |d| d.has_key?(a) && d.has_key?(b) }.map { |d| f.call(d[b]) / f.call(d[a]) }
        n, wins = ratio.size, ratio.count(&.> 1)
        p = Math.min(1.0, 2 * (0..Math.min(wins, n - wins)).sum { |k| choose(n, k) } / 2.0 ** n)
        lo, hi = ci.call(-> { resample.call(ratio).median })
        puts "  paired #{b}/#{a} #{name} median #{pct(ratio.median)}  95% CI [#{pct(lo)}, #{pct(hi)}]" \
             "  #{b} higher #{wins}/#{n}, sign p=#{"%.3f" % p}"
      end
    end
  end
end
