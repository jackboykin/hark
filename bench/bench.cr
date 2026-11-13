# bench <tool> args...: the bench's readers of its own output.
require "./overload"
require "./live/compare"

USAGE = "usage: bench overload|compare ..."

case ARGV.shift?
when "overload"     then Overload.main(ARGV)
when "compare"      then Compare.main(ARGV)
when "-h", "--help" then puts USAGE
else                     abort USAGE
end
