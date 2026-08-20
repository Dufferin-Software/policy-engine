#!/usr/bin/env bash
# Run every policy-engine integration suite sequentially and summarise
# pass/fail. Each suite boots its own netsim topology.
#
# Usage:
#   python/run_all.sh [PKG_DIR]
#
# PKG_DIR defaults to ../.. (where dpkg-buildpackage drops the .debs).
# Override the suite list with SUITES="a b c" python/run_all.sh.
# Skip suites with SKIP="scale_test policy_performance" python/run_all.sh.
#
# Which packages land on which node is declared per node in each suite's
# topology yaml ('packages' globs, resolved against PKG_DIR via
# --package-dir); pytest validates the globs before starting any VMs.

set -u
cd "$(dirname "$0")"

PKG_DIR="${1:-../..}"
SKIP="${SKIP:-}"
LOG_DIR="${LOG_DIR:-pytest-logs}"
mkdir -p "$LOG_DIR"

# Auto-discover suites: any tests/<name>/<name>.yaml is a suite.
if [[ -z "${SUITES:-}" ]]; then
  SUITES=""
  for d in tests/*/; do
    name="$(basename "$d")"
    [[ -f "$d/$name.yaml" ]] && SUITES+="$name "
  done
fi

declare -A RESULT
declare -A DURATION
declare -A COUNTS
overall=0
interrupted=0

on_interrupt() {
  interrupted=1
  echo
  echo "=== interrupted; run 'netsim destroy' on the topology if VMs remain" >&2
  trap - INT
  # Re-raise so the exit status reflects the signal.
  kill -INT $$
}
trap on_interrupt INT

for suite in $SUITES; do
  if [[ " $SKIP " == *" $suite "* ]]; then
    RESULT[$suite]=SKIP
    continue
  fi

  topo="tests/$suite/$suite.yaml"
  log="$LOG_DIR/$suite.log"

  echo
  echo "================================================================"
  echo "=== $suite"
  echo "=== topo: $topo"
  echo "================================================================"

  start=$SECONDS
  status=PASS

  # pytest owns the topology: the autouse running_topology fixture boots the
  # VMs and destroys them again, including after a failure.
  if ! poetry run pytest "tests/$suite/" -v \
      --package-dir "$PKG_DIR" 2>&1 | tee "$log"; then
    status=FAIL
  fi
  # Pull the pass/fail/skip counts out of pytest's final summary line
  # (e.g. "==== 1 failed, 2 passed, 3 skipped in 4.56s ===="). A suite can
  # exit 0 while skipping every test, so the counts matter beyond PASS/FAIL.
  summary_line=$(grep -E '^=+ .*(passed|failed|skipped|error|no tests ran)' \
    "$log" | tail -n1)
  if [[ -n "$summary_line" ]]; then
    counts=""
    for kind in failed passed skipped error errors xfailed deselected; do
      n=$(grep -oE "[0-9]+ $kind\b" <<<"$summary_line" | grep -oE '^[0-9]+')
      [[ -n "$n" ]] && counts+="${counts:+, }$n $kind"
    done
    COUNTS[$suite]="$counts"
    # Surface a suite that passed-but-skipped-everything: if there were
    # skips and nothing actually passed, it didn't really test anything.
    if [[ $status == PASS && "$summary_line" != *" passed"* \
          && "$summary_line" == *" skipped"* ]]; then
      status=ALL_SKIPPED
    fi
  fi

  DURATION[$suite]=$((SECONDS - start))
  RESULT[$suite]=$status
  # ALL_SKIPPED is reported but, like an explicit SKIP, doesn't fail the run.
  case "$status" in PASS|ALL_SKIPPED) ;; *) overall=1 ;; esac
done

summary_log="$LOG_DIR/summary.log"
{
  echo
  echo "================================================================"
  echo "=== Summary"
  echo "================================================================"
  printf "%-22s %-12s %8s  %s\n" "SUITE" "RESULT" "TIME(s)" "TESTS"
  for suite in $SUITES; do
    printf "%-22s %-12s %8s  %s\n" \
      "$suite" "${RESULT[$suite]:-?}" "${DURATION[$suite]:-0}" \
      "${COUNTS[$suite]:-}"
  done

  # Call out anything that didn't cleanly pass so failures/skips are easy to
  # spot (and grep) in the persisted log. ALL_SKIPPED and SKIP both count as
  # skips; everything else non-PASS is a failure.
  failed="" skipped=""
  for suite in $SUITES; do
    case "${RESULT[$suite]:-?}" in
      PASS)              ;;
      SKIP|ALL_SKIPPED)  skipped+="$suite (${RESULT[$suite]}) " ;;
      *)                 failed+="$suite (${RESULT[$suite]:-?}) " ;;
    esac
  done
  echo
  [[ -n "$failed" ]]  && echo "FAILED:  $failed"  || echo "FAILED:  none"
  [[ -n "$skipped" ]] && echo "SKIPPED: $skipped" || echo "SKIPPED: none"
  echo
  echo "Logs: $LOG_DIR/<suite>.log"
} | tee "$summary_log"

exit $overall
