/* Reviewed bundled-indicator guards, defined once for every browser path.

   The roster is deliberately fixed in code: manifest data may refresh a
   reviewed snapshot's hash and floors, but it cannot silently add, remove,
   rename, duplicate, or reorder a campaign. Every entry must also carry a
   lowercase SHA-256 pin and valid reviewed floors before any bundle is
   fetched. */

export const EXPECTED_BUNDLED_SET_ROSTER = Object.freeze([
  Object.freeze({ name: 'pegasus', file: 'iocs/pegasus.stix2' }),
  Object.freeze({ name: 'predator', file: 'iocs/predator.stix2' }),
  Object.freeze({ name: 'kingspawn', file: 'iocs/kingspawn.stix2' }),
  Object.freeze({ name: 'triangulation', file: 'iocs/triangulation.stix2' }),
  Object.freeze({ name: 'rcs', file: 'iocs/rcs.stix2' }),
  Object.freeze({ name: 'wintego_helios', file: 'iocs/wintego_helios.stix2' }),
  Object.freeze({ name: 'coruna', file: 'iocs/coruna.stix2' }),
  Object.freeze({ name: 'darksword', file: 'iocs/darksword.stix2' }),
]);

const SHA256_HEX = /^[0-9a-f]{64}$/;

export function hasExpectedBundledSetRoster(sets) {
  return Array.isArray(sets)
    && sets.length === EXPECTED_BUNDLED_SET_ROSTER.length
    && sets.every((set, index) => {
      const expected = EXPECTED_BUNDLED_SET_ROSTER[index];
      return set !== null
        && typeof set === 'object'
        && !Array.isArray(set)
        && set.name === expected.name
        && set.file === expected.file
        && typeof set.sha256 === 'string'
        && SHA256_HEX.test(set.sha256)
        && Number.isSafeInteger(set.min_indicators)
        && set.min_indicators >= 0
        && Number.isSafeInteger(set.min_applicable)
        && set.min_applicable >= 0;
    });
}

/* A bundled indicator set must meet the reviewed floor recorded in the
   manifest before it can influence a scan; a partial, stale, or damaged
   deployed snapshot must be rejected rather than allowed to produce a hollow
   "clear" verdict. The check runs on the main thread (newScanner) and again
   inside the scan worker as defense in depth, so a long-lived page that
   outlives a deployment cannot pair a newer worker with an older floor. */

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
