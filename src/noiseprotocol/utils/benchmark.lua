--- @module "noiseprotocol.utils.benchmark"
--- Common benchmarking utilities for performance testing
--- @class noiseprotocol.utils.benchmark
local benchmark = {}

--- Run a benchmarked operation with warmup and timing
--- @param name string Operation name for display
--- @param func function Function to benchmark
--- @param iterations? integer Number of iterations (default: 100)
--- @return number ms_per_op Milliseconds per operation
function benchmark.benchmark_op(name, func, iterations)
  iterations = iterations or 100

  -- Warmup
  for _ = 1, 3 do
    func()
  end

  -- Actual benchmark
  local start = os.clock()
  for _ = 1, iterations do
    func()
  end
  local elapsed = os.clock() - start

  local per_op = (elapsed / iterations) * 1000 -- ms
  local ops_per_sec = iterations / elapsed

  print(string.format("%-30s: %8.3f ms/op, %8.1f ops/sec", name, per_op, ops_per_sec))

  return per_op
end

return benchmark
