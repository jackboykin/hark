# compare <run.sh OUT dir> <A> <B>: run.sh's two sides, pass by pass, then
# cold answer by cold answer; writes the names they disagree on to
# OUT/disagree.tsv.
require "json"
require "../stats"

module Compare
  # One side's answer to one name, as ask writes it: [rcode, ad, ede, answers, ms].
  record Answer, rcode : String, ad : Bool, ede : Array(Int32), rrs : Array(String), ms : Float64 do
    def self.new(pull : JSON::PullParser)
      pull.read_begin_array
      a = new(String.new(pull), Bool.new(pull), Array(Int32).new(pull), Array(String).new(pull), Float64.new(pull))
      pull.read_end_array
      a
    end

    def failed?
      rcode.starts_with?("TIMEOUT") || rcode.starts_with?("ERROR")
    end

    def shape
      rrs.map { |rr| (i = rr.rindex('|')) ? rr[0, i] : rr }.uniq.sort
    end
  end

  # One name's answers in a round, side A's then side B's.
  struct Row
    include JSON::Serializable
    @[JSON::Field(key: "n")]
    getter name : String
    @[JSON::Field(key: "r")]
    getter answers : {Answer, Answer}
  end

  def self.pct(v, p)
    v = v.sort
    v.empty? ? 0.0 : v[Math.min(v.size - 1, (p / 100 * v.size).to_i)]
  end

  # The last dump's `stats <name>.<counter>` values.
  def self.plane(log, name)
    v = log.scan(/stats #{name}\.([a-z_.]+)\s+(\d+)/).to_h { |m| {m[1], m[2].to_i64} }
    v unless v.empty?
  end

  def self.bucket(a, b)
    return "both #{a.rcode}" if a.rcode == b.rcode && a.failed?
    return "rcode #{a.rcode}/#{b.rcode}" if a.rcode != b.rcode
    return "ad #{a.ad ? 1 : 0}/#{b.ad ? 1 : 0}" if a.ad != b.ad
    return "shape" if a.shape != b.shape
    a.rrs == b.rrs ? "same" : "addresses"
  end

  def self.main(args)
    dir, a, b = args
    sides = {a, b}
    passes = Hash(String, Array(Array(Row))).new { |h, k| h[k] = [] of Array(Row) }
    Dir.glob("#{dir}/*.jsonl").sort.each do |f|
      passes[f.split('.')[-2]] << File.read_lines(f).map { |l| Row.from_json(l) }
    end
    cold = passes["cold"].flatten

    puts "#{"".ljust(22)} #{a.rjust(10)} #{b.rjust(10)}"
    passes.each do |name, rounds|
      rows = rounds.flatten
      ms = (0..1).map { |i| rows.map(&.answers[i]).reject(&.failed?).map(&.ms) }
      {50, 90, 99}.each do |p|
        o, n = pct(ms[0], p), pct(ms[1], p)
        puts "#{name} ms p#{p.to_s.ljust(14)} #{"%10.2f" % o} #{"%10.2f" % n}  #{"%+.1f" % (o != 0 ? 100 * (n - o) / o : 0.0)}%"
      end
      # Cold times cluster by hop count; a percentile on the gap between
      # clusters swings as a few names cross it. Pairing each name's two
      # answers in a round does not.
      d = rows.reject(&.answers.any?(&.failed?)).map { |row| row.answers[1].ms - row.answers[0].ms }
      puts "#{name} ms #{b}-#{a} paired   median #{"%+.2f" % d.median}  mean #{"%+.2f" % d.mean}"
    end

    table = Array.new(2) { Hash(String, Array(Float64)).new { |h, k| h[k] = [] of Float64 } }
    passes["cold"].each do |rnd|
      2.times do |i|
        answers = rnd.map(&.answers[i])
        table[i]["cold ad"] << answers.count(&.ad).to_f
        table[i]["cold servfail"] << answers.count { |x| x.rcode == "SERVFAIL" }.to_f
        table[i]["cold failed"] << answers.count(&.failed?).to_f
      end
    end
    sides.each_with_index do |side, i|
      Dir.glob("#{dir}/#{side}.*.mem").sort.each do |mem|
        base = mem.rchop(".mem")
        vm = File.read_lines(mem).to_h { |l| k, v = l.split(':'); {k, v} }
        table[i]["VmHWM KiB"] << vm["VmHWM"].split[0].to_f
        log = File.read("#{base}.log")
        if r = plane(log, "resolver")
          table[i]["exchanges"] << (r["exchanges.udp"] + r["exchanges.tcp"]).to_f
          table[i]["upstream tcp"] << r["exchanges.tcp"].to_f
          table[i]["upstream timeouts"] << r["faults.timeout"].to_f
        end
        if t = plane(log, "trust")
          table[i]["bogus"] << t["bogus"].to_f
        end
        if s = plane(log, "store")
          table[i]["store KiB"] << s["held"].to_f
          table[i]["store facts"] << s["facts"].to_f
        end
      end
    end
    ["cold ad", "cold servfail", "cold failed", "exchanges", "upstream tcp", "upstream timeouts", "bogus", "store KiB", "store facts", "VmHWM KiB"].each do |k|
      o, n = table.map { |x| (v = x[k]?) && !v.empty? ? "%10.1f" % v.median : "-".rjust(10) }
      puts "#{k.ljust(22)} #{o} #{n}"
    end

    per = Hash(String, {Array(Float64), Array(Float64)}).new { |h, k| h[k] = {[] of Float64, [] of Float64} }
    cold.each { |row| 2.times { |i| per[row.name][i] << row.answers[i].ms } }
    moved = per.map { |n, (x, y)| {y.median - x.median, n} }.sort
    named = ->(m : Array({Float64, String})) { "[" + m.join(", ") { |v, n| "('#{n}', #{v.round.to_i})" } + "]" }
    puts "#{b} faster most: #{named.call(moved.first(6))}"
    puts "#{b} slower most: #{named.call(moved.last(6))}"
    puts "names #{b} is faster on (median cold): #{moved.count { |v, _| v < 0 }}/#{moved.size}"

    buckets = cold.group_by { |row| bucket(*row.answers) }.transform_values(&.map(&.name))
    agree = {"same", "addresses"}
    puts "cold answers, #{cold.size} over #{passes["cold"].size} rounds:"
    buckets.to_a.sort_by { |_, names| -names.size }.each do |k, names|
      puts "  #{names.size.to_s.rjust(8)}  #{k}" + (agree.includes?(k) ? "" : "  e.g. " + names.uniq.sort.first(4).join(' '))
    end
    ede = cold.flat_map { |row| (0..1).flat_map { |i| row.answers[i].ede.map { |e| {sides[i], e} } } }.tally
    puts "ede: {" + ede.to_a.sort_by { |_, c| -c }.first(12).join(", ") { |(s, e), c| "('#{s}', #{e}): #{c}" } + "}"
    File.open(File.join(dir, "disagree.tsv"), "w") do |f|
      buckets.each { |k, names| names.uniq.sort.each { |n| f.puts "#{k}\t#{n}" } unless agree.includes?(k) }
    end
  end
end
