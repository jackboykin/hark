# sys fold <comm> < perf script -F comm,event,period,ip,sym (with -g)
# sys report <dir> <seconds>: sys.sh's report.
#
# fold sums one run's samples: each cycle goes to one part (hark's own code,
# the syscall its kernel stack sits under, softirq, other kernel time in
# hark, or another task on the core), and hark's own code by function, in
# cycles and user instructions.
#
# report divides by the queries asked in the window and takes each side's
# median over its rounds: its parts with their top kernel symbols, hark's
# functions, and syscalls per query from strace. Each later side is then set
# against the first, part by part and function by function, with the range
# of the first side's rounds beside each figure as its noise.
require "json"
require "./stats"

module Sys
  alias Counts = Hash(String, Int64)

  # One run's samples, as fold writes them and report reads them.
  record Fold, parts : Counts, syms : Hash(String, Counts), fns : Hash(String, Counts) do
    include JSON::Serializable
  end

  KERNEL  = 0xffff800000000000_u64
  SYSCALL = /^(?:__x64_sys_|__se_sys_|__do_sys_)(\w+)/
  SOFTIRQ = {"handle_softirqs", "__do_softirq", "net_rx_action"}
  GENERIC = /__func_\d+|__anon_\d+|'\d+$/
  HEAD    = /^(.*\S)\s+(\S+)\s+(\S+)\s*$/

  def self.part(comm, task, frames)
    return "other task: #{task}" if task != comm
    return "hark" if frames[0][0].to_u64(16) < KERNEL
    frames.each do |_, s|
      return "sys #{$1}" if s =~ SYSCALL
      return "softirq" if SOFTIRQ.any? { |p| s.starts_with?(p) }
    end
    "kernel, no syscall"
  end

  def self.fold(comm)
    parts = Counts.new(0)
    syms = Hash(String, Counts).new { |h, k| h[k] = Counts.new(0) }
    fns = {"cycles" => Counts.new(0), "instructions" => Counts.new(0)}
    STDIN.each_line.chunk(&.blank?).each do |blank, block|
      next if blank
      _, task, period, event = HEAD.match!(block[0])
      event, period = event.rstrip(':').split(':')[0], period.to_i64
      frames = block[1..].map { |f| ip_sym = f.lstrip.split(2); {ip_sym[0], ip_sym[1]? || "?"} }
      frames = [{"0", "?"}] if frames.empty?
      p, leaf = part(comm, task.strip, frames), frames[0][1].strip.gsub(GENERIC, "")
      fns[event][leaf] += period if p == "hark"
      if event == "cycles"
        parts[p] += period
        syms[p][leaf] += period
      end
    end
    top = syms.transform_values { |s| s.to_a.sort_by { |_, n| -n }.first(3).to_h }
    Fold.new(parts, top, fns).to_json(STDOUT)
  end

  record Run, parts : Hash(String, Float64), syms : Hash(String, Counts), qps : Float64, lost : Int64,
    cyc : Hash(String, Float64), ins : Hash(String, Float64) do
    def cycles
      parts.values.sum
    end

    def instructions
      ins.values.sum
    end
  end

  def self.med(rs : Array(Run), & : Run -> Float64)
    rs.map { |r| yield r }.median
  end

  def self.spread(rs : Array(Run), & : Run -> Float64)
    v = rs.map { |r| yield r }
    (v.max - v.min) / 2
  end

  def self.dnsperf(path)
    t = File.read(path)
    num = ->(k : String) { t.match!(/#{k}:\s+([\d.]+)/)[1].to_f }
    {num.call("Queries per second"), num.call("Queries completed").to_i64, num.call("Queries lost").to_i64}
  end

  def self.report(dir, secs)
    runs = Hash(String, Array(Run)).new { |h, k| h[k] = [] of Run }
    Dir.glob("#{dir}/*-*.json").sort.each do |path|
      side = File.basename(path, ".json").split('-', 2)[1]
      qps, _, lost = dnsperf(path.rchop(".json") + ".load")
      d = Fold.from_json(File.read(path))
      per = ->(c : Counts) { c.transform_values { |v| v / (qps * secs) } }
      runs[side] << Run.new(per.call(d.parts), d.syms, qps, lost, per.call(d.fns["cycles"]), per.call(d.fns["instructions"]))
    end
    sides = runs.keys.sort_by { |s| Dir.glob("#{dir}/*-#{s}.json").min_of { |p| File.info(p).modification_time } }

    sides.each do |s|
      rs = runs[s]
      total = med(rs, &.cycles)
      puts "#{s}: #{rs.size} runs at #{"%.0f" % med(rs, &.qps)} qps, #{rs.sum(&.lost)} lost"
      puts "  #{"%8.0f" % total} cycles per query"
      rs[0].parts.keys.sort_by { |p| -rs[0].parts[p] }.each do |p|
        c = med(rs) { |r| r.parts.fetch(p, 0.0) }
        next if c / total < 0.002
        syms = rs[0].syms[p]
        top = p == "hark" ? "" : syms.join(", ") { |k, n| "#{k} #{"%.0f" % (100.0 * n / syms.values.sum)}%" }
        puts "  #{"%8.0f" % c} #{"%5.1f" % (100 * c / total)}%  #{p.ljust(22)} #{top}"
      end
      puts "  hark's own code: #{"%.0f" % med(rs, &.instructions)} instructions per query; top functions, cycles and instructions per query:"
      rs[0].cyc.keys.sort_by { |k| -rs[0].cyc[k] }.first(12).each do |k|
        puts "  #{"%8.0f" % med(rs) { |r| r.cyc.fetch(k, 0.0) }} #{"%8.0f" % med(rs) { |r| r.ins.fetch(k, 0.0) }}  #{k[0, 100]}"
      end
      if File.exists?(trace = "#{dir}/#{s}.strace")
        _, done, _ = dnsperf("#{dir}/#{s}.count")
        rows = File.read_lines(trace).map(&.split).select { |f| f.size >= 5 && f[-1] != "total" && f[3] =~ /\A\d+\z/ }.map do |f|
          {f[3].to_i64 / done, (f.size == 6 ? f[4].to_i64 : 0) / done, f[-1]}
        end
        listed = rows.sort.reverse.select { |c, _, _| c >= 0.01 }.join(", ") { |c, e, n| "#{n} #{"%.2f" % c}" + (e != 0 ? " (#{"%.2f" % e} failed)" : "") }
        puts "  syscalls per query (strace -c over #{done} queries): #{listed}; #{"%.2f" % rows.sum(&.[0])} in all"
      end
      puts
    end

    a = runs[sides[0]]
    sides[1..].each do |s|
      b = runs[s]
      puts "#{s} - #{sides[0]}, per query, ± half the range of #{sides[0]}'s runs:"
      {"cycles" => ->(r : Run) { r.cycles }, "hark's instructions" => ->(r : Run) { r.instructions }}.each do |name, f|
        d = med(b, &f) - med(a, &f)
        puts "  #{"%+8.0f" % d} ± #{"%.0f" % spread(a, &f)}  #{name} (#{"%+.2f" % (100 * d / med(a, &f))}%)"
      end
      { {"part", "cycles", ->(r : Run) { r.parts }}, {"function", "instructions", ->(r : Run) { r.ins }} }.each do |by, unit, key|
        delta = (a + b).flat_map { |r| key.call(r).keys }.uniq.to_h do |k|
          {k, med(b) { |r| key.call(r).fetch(k, 0.0) } - med(a) { |r| key.call(r).fetch(k, 0.0) }}
        end
        puts "  by #{by}, #{unit}:"
        delta.to_a.sort_by { |_, d| -d.abs }.first(10).each do |k, d|
          puts "  #{"%+8.0f" % d} ± #{"%.0f" % spread(a) { |r| key.call(r).fetch(k, 0.0) }}  #{k[0, 100]}"
        end
      end
      puts
    end
  end

  def self.main(args)
    case args[0]?
    when "fold"   then fold(args[1])
    when "report" then report(args[1], args[2].to_f)
    else               abort "usage: bench sys fold <comm> | report <dir> <seconds>"
    end
  end
end
