/* The reviewed-floor guard, defined once and imported by both scan paths.

   A bundled indicator set must meet the reviewed floor recorded in the
   manifest before it can influence a scan; a partial, stale, or damaged
   deployed snapshot must be rejected rather than allowed to produce a hollow
   "clear" verdict. The check runs on the main thread (newScanner) and again
   inside the scan worker as defense in depth, so a long-lived page that
   outlives a deployment cannot pair a newer worker with an older floor. It
   lives here so those two enforcement points can never silently diverge. */

export function meetsReviewedFloor(set, stats) {
  return Number.isSafeInteger(set.min_indicators)
    && set.min_indicators >= 0
    && Number.isSafeInteger(set.min_applicable)
    && set.min_applicable >= 0
    && Number.isSafeInteger(stats?.extracted)
    && stats.extracted >= set.min_indicators
    && Number.isSafeInteger(stats?.applicable)
    && stats.applicable >= set.min_applicable;
}
