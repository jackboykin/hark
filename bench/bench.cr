# bench <tool> args...: the bench's readers of its own output.
require "./an"

USAGE = "usage: bench an ..."

case ARGV.shift?
when "an"           then An.main(ARGV)
when "-h", "--help" then puts USAGE
else                     abort USAGE
end
