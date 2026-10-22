# bench <tool> args...: the bench's readers of its own output.
require "./an"
require "./sys"

USAGE = "usage: bench an|sys ..."

case ARGV.shift?
when "an"           then An.main(ARGV)
when "sys"          then Sys.main(ARGV)
when "-h", "--help" then puts USAGE
else                     abort USAGE
end
