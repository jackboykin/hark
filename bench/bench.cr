# bench <tool> args...: the bench's readers of its own output.
require "./an"
require "./sys"
require "./overload"
require "./live/compare"

USAGE = "usage: bench an|sys|overload|compare ..."

case ARGV.shift?
when "an"           then An.main(ARGV)
when "sys"          then Sys.main(ARGV)
when "overload"     then Overload.main(ARGV)
when "compare"      then Compare.main(ARGV)
when "-h", "--help" then puts USAGE
else                     abort USAGE
end
