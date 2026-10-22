# Python's statistics, as the bench's reports read them.
class Array(T)
  def mean : Float64
    sum(0.0) / size
  end

  def median : Float64
    s = sort
    m = size // 2
    size.odd? ? s[m].to_f : (s[m - 1] + s[m]) / 2
  end

  # The sample standard deviation.
  def stdev : Float64
    m = mean
    Math.sqrt(sum(0.0) { |x| (x - m) ** 2 } / (size - 1))
  end
end
