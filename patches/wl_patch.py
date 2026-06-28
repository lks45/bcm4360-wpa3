#!/usr/bin/env python3
"""Validated binary patcher for the broadcom-sta closed blob (wlc_hybrid.o_amd64).

Each patch validates the expected ORIGINAL bytes before writing, so a stale offset
can never silently corrupt the blob. Patches must be length-preserving (we relink,
not re-lay-out). Run with --apply to write; default is dry-run.

.text maps vaddr V -> file offset V + 0x40 (sh_addr=0, sh_offset=0x40).
"""
import sys, shutil, os

# blob path = argv[1] (or $BLOB); the .orig backup is written next to it
TARGET = (sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-")
          else os.environ.get("BLOB", "wl-src/lib/wlc_hybrid.o_amd64"))
BACKUP = TARGET + ".orig"
TEXT_BASE = 0x40  # file offset of .text vaddr 0

# (name, file_offset, expected_old_hex, new_hex, rationale)
PATCHES = [
    ("P1-auth-clamp-passthrough", 0x47d8d, "0f95c0", "4489f0",
     "wlc_doiovar @0x47d4d: 'setne %al' -> 'mov %r14d,%eax'. The following "
     "'mov %ax,0x94(%r15)' then stores the REQUESTED auth value verbatim into "
     "bsscfg+0x94 instead of clamping nonzero->1. Lets us set auth alg=3 (SAE)."),
]

def main():
    apply = "--apply" in sys.argv
    if not os.path.exists(TARGET):
        print("ERROR: target missing:", TARGET); sys.exit(1)
    data = bytearray(open(TARGET, "rb").read())
    print("target: %s (%d bytes)  mode: %s" % (TARGET, len(data), "APPLY" if apply else "dry-run"))
    changed = False
    ok = True
    for name, off, oldhex, newhex, why in PATCHES:
        old = bytes.fromhex(oldhex); new = bytes.fromhex(newhex)
        if len(old) != len(new):
            print("  [ERROR] %s: length mismatch %d!=%d" % (name, len(old), len(new))); ok = False; continue
        cur = bytes(data[off:off+len(old)])
        if cur == new:
            print("  [already] %s @0x%x (== %s)" % (name, off, newhex)); continue
        if cur != old:
            print("  [MISMATCH] %s @0x%x: found %s, expected %s -- NOT applying" % (name, off, cur.hex(), oldhex)); ok = False; continue
        print("  [patch]   %s @0x%x: %s -> %s" % (name, off, oldhex, newhex))
        print("            %s" % why)
        if apply:
            data[off:off+len(new)] = new; changed = True
    if not ok:
        print("RESULT: validation problems above; nothing written."); sys.exit(2)
    if apply and changed:
        if not os.path.exists(BACKUP):
            shutil.copy(TARGET, BACKUP); print("backed up pristine blob -> %s" % BACKUP)
        open(TARGET, "wb").write(data)
        print("WROTE %d patched bytes." % len(data))
    elif apply:
        print("nothing to change (all patches already applied).")
    else:
        print("(dry-run; pass --apply to write)")

if __name__ == "__main__":
    main()
