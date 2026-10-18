# Merge every SARIF run into a single run.
#
# Snyk emits one run per project it finds in the container image (the OS
# package manager plus every application manifest), which exceeds the limit of
# 20 runs per file that GitHub code scanning enforces:
#   "rejecting SARIF, as there are more runs than allowed (21 > 20)"
#
# The rules of all runs are collected into one deduplicated list and the
# results are concatenated. Per-result rule indices are dropped, as ruleId
# alone identifies the rule once the indices no longer match.
if (.runs | length) == 0 then
  .
else
  ([.runs[].tool.driver.rules[]?] | group_by(.id) | map(.[0])) as $rules
  | ([.runs[].results[]? | del(.ruleIndex) | del(.rule.index)]) as $results
  | .runs = [.runs[0] | .tool.driver.rules = $rules | .results = $results]
end
