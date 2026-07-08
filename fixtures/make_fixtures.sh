#!/usr/bin/env bash
# Builds two synthetic sysdiagnose archives for demos and end-to-end tests:
#   web/fixtures/sysdiagnose_demo_clean.tar.gz
#   web/fixtures/sysdiagnose_demo_infected.tar.gz
# The "infected" one seeds a real Pegasus process-name indicator taken from
# the bundled Amnesty STIX2 file, so it exercises the genuine match path.
# Requires: jq, bsdtar (macOS default tar).
set -euo pipefail
cd "$(dirname "$0")/.."

IOC_PROC=$(jq -r '.objects[] | select(.type=="indicator") | .pattern' web/iocs/pegasus.stix2 \
  | grep -oE "process:name\s*=?\s*'[^']+'" | head -1 | sed -E "s/.*'([^']+)'/\1/")
[ -n "$IOC_PROC" ] || { echo "could not extract a process IOC from pegasus.stix2" >&2; exit 1; }
echo "Seeding infected fixture with Pegasus process indicator: $IOC_PROC"

STAGING="/private/var/db/com.apple.xpc.roleaccountd.staging"
OUT="web/fixtures"
mkdir -p "$OUT"

make_tree() { # $1 = tmpdir root, $2 = infected|clean
  local root="$1/sysdiagnose_2026.07.07_19-00-00+0000_iPhone-OS_iPhone_23A341"
  mkdir -p "$root/crashes_and_spins" "$root/system_logs.logarchive/Extra"

  # --- shutdown.0.log: iOS 26 format (rotated filename; "After Xs, these
  #     clients are still here:" headers; tab-indented client lines whose
  #     paths carry a trailing binary-UUID component). Several reboot
  #     blocks; delays reset each reboot. ---
  {
    for i in 1 2 3; do
      echo "After 1.26s, these clients are still here:"
      printf '\t\tremaining client pid: 155 (/usr/libexec/nfcd/EBFB3E7F-4CA4-3656-8E9C-8CCF5995C34A)\n'
      if [ "$2" = infected ] && [ "$i" -ge 2 ]; then
        printf '\t\tremaining client pid: 2143 (%s/%s/AAAA1111-B896-3E7F-A6CC-577F0A547BB1)\n' "$STAGING" "$IOC_PROC"
      fi
      echo "After 1.77s, these clients are still here:"
      printf '\t\tremaining client pid: 155 (/usr/libexec/nfcd/EBFB3E7F-4CA4-3656-8E9C-8CCF5995C34A)\n'
      if [ "$2" = infected ] && [ "$i" -ge 2 ]; then
        printf '\t\tremaining client pid: 2143 (%s/%s/AAAA1111-B896-3E7F-A6CC-577F0A547BB1)\n' "$STAGING" "$IOC_PROC"
      fi
    done
  } > "$root/system_logs.logarchive/Extra/shutdown.0.log"

  # --- ps.txt: fixed-width columns; COMMAND offset must match the header ---
  local fmt='%-16s %3s %5s %5s %4s %4s %-8s %8s %s\n'
  {
    printf "$fmt" USER UID PID PPID %CPU %MEM STARTED TIME COMMAND
    printf "$fmt" root 0 1 0 0.0 0.1 Tue07PM 0:12.34 "/sbin/launchd"
    printf "$fmt" mobile 501 211 1 0.2 0.5 Tue07PM 0:01.02 "/usr/sbin/mediaserverd"
    printf "$fmt" mobile 501 340 1 0.0 0.3 Tue07PM 0:00.55 "/Applications/Music.app/Music --launchedByApp"
    if [ "$2" = infected ]; then
      printf "$fmt" root 0 2143 1 0.1 0.2 Tue07PM 0:00.11 "$STAGING/$IOC_PROC"
    fi
  } > "$root/ps.txt"

  # --- crash logs ---
  cat > "$root/crashes_and_spins/MobileSafari-2026-07-05-101112.ips" <<'EOF'
{"app_name":"MobileSafari","timestamp":"2026-07-05 10:11:12.00 -0700","name":"MobileSafari","bug_type":"309","os_version":"iPhone OS 17.2.1 (21C66)","incident_id":"11111111-2222-3333-4444-555555555555"}
{"procName":"MobileSafari","procPath":"/Applications/MobileSafari.app/MobileSafari","parentProc":"launchd","pid":340,"exception":{"codes":"0x0","type":"EXC_CRASH"}}
EOF
  if [ "$2" = infected ]; then
    cat > "$root/crashes_and_spins/${IOC_PROC}-2026-07-06-120311.ips" <<EOF
{"app_name":"$IOC_PROC","timestamp":"2026-07-06 12:03:11.00 -0700","name":"$IOC_PROC","bug_type":"309","os_version":"iPhone OS 17.2.1 (21C66)","incident_id":"66666666-7777-8888-9999-000000000000"}
{"procName":"$IOC_PROC","procPath":"$STAGING/$IOC_PROC","parentProc":"launchd","pid":2143,"exception":{"codes":"0x0","type":"EXC_CRASH"}}
EOF
  fi

  # decoys the scanner must ignore (deterministic bytes: the fixtures are
  # tracked in git, so a rebuild must reproduce them byte-for-byte)
  python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)) * 16)" > "$root/ignored_blob.bin"
  echo "sysdiagnose metadata" > "$root/sysdiagnose.log"
}

for kind in clean infected; do
  tmp=$(mktemp -d)
  make_tree "$tmp" "$kind"
  # Deterministic archive: fixed mtimes, sorted entry order, no owner
  # metadata, and gzip without its timestamp header.
  find "$tmp" -exec touch -t 202607071900 {} +
  (cd "$tmp" && find . -mindepth 1 -print | LC_ALL=C sort \
    | tar -cn --uid 0 --gid 0 -T - -f - | gzip -n) \
    > "$OUT/sysdiagnose_demo_$kind.tar.gz"
  rm -rf "$tmp"
done

ls -la "$OUT"
