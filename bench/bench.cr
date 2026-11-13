# bench <tool> args...: the bench's readers of its own output.
require "./live/compare"

USAGE = "usage: bench compare ..."

case ARGV.shift?
when "compare"      then Compare.main(ARGV)
when "-h", "--help" then puts USAGE
else                     abort USAGE
end
