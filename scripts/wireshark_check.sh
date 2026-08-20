#!/usr/bin/env bash
#
# Cross-check the BER this crate emits against Wireshark's gsm_map dissector.
#
# A BER round-trip cannot catch a shared encode/decode bug: get a tag wrong in
# both directions and the round-trip still passes, and a member encoded out of
# order is silently dropped rather than rejected. Wireshark ships the TS 29.002
# ASN.1 compiled into its dissector and does not share our bugs, so it is a real
# third-party answer to "did every member we sent arrive, named, in order?".
#
# examples/wireshark_vectors.rs emits one maximal instance of every operation as
# a full MAP -> TCAP -> SCCP frame; text2pcap -l 142 is the SS7 SCCP link type,
# so tshark dissects sccp:tcap:gsm_map with no MTP3/M3UA/SCTP framing to fake.
# The example also prints, per frame, how many top-level members it set — this
# script asserts the dissector names back exactly that many, with no BER errors.
#
# Needs tshark + text2pcap and python3.
#
# Wireshark carries a compiled copy of the TS 29.002 ASN.1, so the dissector is
# only a valid oracle if that copy is at least as new as the spec revision the
# vectors target. It is not: 4.2 renders mo-ForwardSM where 4.6 renders
# mo-forwardSM, does not know the resetContext-v3 context, and rejects the newer
# members of sendRoutingInfo, lcs-MOLR and lcs-LocationNotification with "this
# field lies beyond the end of the known sequence definition". Those are gaps in
# the oracle, not in the encoder, but they are indistinguishable from real
# encoder bugs in the output, so refuse to run rather than report either one.

set -euo pipefail

# Lowest Wireshark whose gsm_map dissector knows every member the vectors assert.
WS_MINIMUM=4.6
cd "$(dirname "$0")/.."

for tool in text2pcap tshark python3; do
    command -v "$tool" >/dev/null || {
        echo "[!] $tool not found (Wireshark CLI tools + python3 required)" >&2
        exit 127
    }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Keep tshark off the user's own (possibly unreadable) profile.
export WIRESHARK_CONFIG_DIR="$work/wireshark"
mkdir -p "$WIRESHARK_CONFIG_DIR"

echo "[*] emitting vectors..."
cargo run --quiet --example wireshark_vectors >"$work/vectors.hex" 2>"$work/expected.tsv"

banner="$(tshark --version 2>/dev/null | head -1)"
echo "[*] $banner"
ws_version="$(sed -n 's/^TShark (Wireshark) \([0-9]*\.[0-9]*\).*/\1/p' <<<"$banner")"
if [ -z "$ws_version" ]; then
    echo "[!] could not read a version out of: $banner" >&2
    exit 1
fi
if [ "$(printf '%s\n' "$WS_MINIMUM" "$ws_version" | sort -V | head -1)" != "$WS_MINIMUM" ]; then
    echo "[!] this check needs Wireshark >= $WS_MINIMUM as its reference decoder, found $ws_version." >&2
    echo "[!] An older dissector predicts the wrong member set and would fail frames the" >&2
    echo "[!] encoder gets right. Install a newer Wireshark rather than relaxing this." >&2
    exit 1
fi

echo "[*] text2pcap -l 142 (SS7 SCCP)..."
if ! text2pcap -l 142 "$work/vectors.hex" "$work/vectors.pcap" >"$work/text2pcap.log" 2>&1; then
    echo "[!] text2pcap failed:" >&2
    cat "$work/text2pcap.log" >&2
    exit 1
fi
[ -s "$work/vectors.pcap" ] || {
    echo "[!] text2pcap produced an empty capture:" >&2
    cat "$work/text2pcap.log" >&2
    exit 1
}

# SMS reassembly is stateful across frames: a synthetic TPDU in one vector can
# leave the gsm_sms dissector waiting for a continuation and swallow the frame
# after it. Every vector here is a complete message, so turn it off -- but only
# with the preferences this build actually has, since tshark treats an unknown
# -o as fatal and older releases do not carry all of them.
prefs=()
supported="$(tshark -G defaultprefs 2>/dev/null | sed 's/^#//')"
for pref in gsm_sms.reassemble gsm_sms.reassemble_with_lower_layers_info; do
    if grep -q "^${pref}:" <<<"$supported"; then
        prefs+=(-o "${pref}:FALSE")
    else
        echo "[*] note: this tshark has no ${pref}, leaving it at its default"
    fi
done

echo "[*] dissecting..."
if ! tshark -r "$work/vectors.pcap" -V ${prefs[@]+"${prefs[@]}"} \
    >"$work/dissection.txt" 2>"$work/tshark.log"; then
    echo "[!] tshark failed:" >&2
    cat "$work/tshark.log" >&2
    exit 1
fi
[ -s "$work/dissection.txt" ] || {
    echo "[!] tshark dissected nothing. stderr was:" >&2
    cat "$work/tshark.log" >&2
    exit 1
}

python3 - "$work/expected.tsv" "$work/dissection.txt" <<'PY'
import re
import sys

# Wireshark 4.4 started writing the block type into the frame line ("Frame 1:
# Packet, 97 bytes on wire"); 4.2 and earlier go straight to the length. Match
# the part both spell the same way.
FRAME = re.compile(r"^Frame \d+:")

expected_path, dissection_path = sys.argv[1], sys.argv[2]

expected = []
for line in open(expected_path):
    label, kind, count = line.rstrip("\n").split("\t")
    expected.append((label, kind, int(count)))

# Split the -V output into frames. Operation frames keep only the gsm_map
# subtree; context and error frames need the whole frame, because the dialogue
# portion and the error code live in the TCAP tree above it.
frames, current, in_map = [], None, False
whole, current_whole = [], None
for line in open(dissection_path).read().splitlines():
    if FRAME.match(line):
        if current is not None:
            frames.append(current)
            whole.append(current_whole)
        current, current_whole, in_map = [], [], False
        continue
    if current is None:
        continue
    current_whole.append(line)
    if line.startswith("GSM Mobile Application"):
        in_map = True
        continue
    if in_map:
        # A sibling protocol tree (an SMS TPDU inside sm-RP-UI) starts at
        # column 0 and belongs to another dissector.
        if line and not line.startswith(" "):
            in_map = False
            continue
        current.append(line)
if current is not None:
    frames.append(current)
    whole.append(current_whole)

SKIP = ("invokeID:", "opCode:", "errorCode:", "localValue:", "Padding:", "Component:",
        "invoke", "returnResultLast", "returnError", "resultretres", "[")
BITFLAG = re.compile(r"^[01.]{4} [01.]{4} = ")


def members(lines, indent):
    """The operation's own member lines, at exactly one indentation level.

    A BER error *deeper* than the member level is the dissector objecting to the
    synthetic payload inside a member this crate carries opaquely — not an
    encoder problem, and not something a real payload would trigger. An error at
    or above the member level is ours. Either way, a member that goes missing
    still fails the count, and a payload bad enough to abort the frame truncates
    the dissection and fails it too.
    """
    out, errors = [], []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        depth = len(line) - len(line.lstrip(" "))
        if "BER Error" in stripped or "Malformed" in stripped:
            if depth <= indent:
                errors.append(stripped)
            continue
        if depth != indent:
            continue
        if stripped.startswith(SKIP):
            continue
        # A bit-mask member (SS-Status, an ODB mask) renders each named bit at
        # the same depth as the member itself. Those are its bits, not members.
        if BITFLAG.match(stripped):
            continue
        out.append(stripped.split(":", 1)[0].split(" [", 1)[0])
    return out, errors


failures = 0
if len(frames) != len(expected):
    print("  FAIL  %d frames dissected, %d emitted" % (len(frames), len(expected)),
          file=sys.stderr)
    failures += 1

for (label, kind, want), lines, all_lines in zip(expected, frames, whole):
    if kind in ("acn", "error", "opname"):
        lines = all_lines
        if kind == "opname":
            kind = "error"   # same "localValue: <name> (<code>)" rendering
        # The dialogue portion and the error code sit outside the gsm_map
        # subtree, so these two check the whole frame for the rendered name.
        # An ACN renders as "...: <oid> (<name>)"; an error code as
        # "localValue: <name> (<code>)".
        needle = ("(%s)" % label if kind == "acn"
                  else "localValue: %s (" % label)
        hit = any(needle in ln for ln in lines)
        if hit:
            print("  ok    %-48s %s resolves" % (label, kind))
        else:
            print("  FAIL  %-48s %s did not resolve" % (label, kind), file=sys.stderr)
            failures += 1
        continue
    indent = 16 if kind in ("result", "error_param_choice") else 12
    got, errors = members(lines, indent)
    if errors:
        print("  FAIL  %-36s %s" % (label, errors[0]), file=sys.stderr)
        failures += 1
    elif len(got) != want:
        print("  FAIL  %-36s dissector named %d of %d members" % (label, len(got), want),
              file=sys.stderr)
        print("        got: %s" % ", ".join(got), file=sys.stderr)
        failures += 1
    else:
        print("  ok    %-36s %2d members named back" % (label, want))

if failures:
    print("\nFAIL: %d Wireshark cross-check(s) failed" % failures, file=sys.stderr)
    sys.exit(1)
operations = sum(1 for _, k, _ in expected if k in ("invoke", "result"))
params = sum(1 for _, k, _ in expected if k.startswith("error_param"))
contexts = sum(1 for _, k, _ in expected if k == "acn")
errors_checked = sum(1 for _, k, _ in expected if k == "error")
opnames = sum(1 for _, k, _ in expected if k == "opname")
print("\nPASS: Wireshark named back every member of %d operations and %d error "
      "parameters, and resolved %d operation names, %d application contexts "
      "and %d error codes"
      % (operations, params, opnames, contexts, errors_checked))
PY

# Every frame must reach the gsm_map dissector at all.
frames_total="$(wc -l <"$work/expected.tsv")"
reached="$(tshark -r "$work/vectors.pcap" -T fields -e frame.protocols 2>/dev/null |
    grep -c 'sccp:tcap:gsm_map' || true)"
if [ "$reached" -ne "$frames_total" ]; then
    echo "FAIL: only $reached of $frames_total frames reached gsm_map" >&2
    exit 1
fi
echo "PASS: all $frames_total frames dissect as sccp:tcap:gsm_map"
