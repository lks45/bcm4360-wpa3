# WPA3-SAE + 802.11w on the Broadcom BCM4360 (closed `wl` blob)

Apple/Broadcom never gave the **BCM4360** (`14e4:43a0`) WPA3. Its only Linux driver is the
closed `broadcom-sta` (`wl`) blob; `brcmfmac` can't drive it. This adds **WPA3-SAE + full
802.11w PMF** to that closed blob — entirely from host software, **no firmware source**.

Proven on-air vs a WPA3-only, MFP-required AP: SAE auth → assoc → 4-way → CCMP data, stable,
and resistant to **deauth-flood** *and* **SA-Query teardown** attacks.

## How it works

The blob is a **non-stripped, relocatable ELF `.o`** (not a final firmware image) — that is the
whole reason this works. We don't rewrite it; we **link new C against it** and **redirect a few
call sites**:

- `wpa_supplicant` runs SAE + the 4-way (the blob's crypto is SHA-1-only; SAE needs SHA-256).
- A small cfg80211 glue (`wl_cfg80211_hybrid.c`, `wl_linux.c`) bridges auth/assoc/keys.
- Three build steps make the blob hookable:
  1. **P1 byte-patch** — un-clamp the `auth` iovar so it accepts SAE (alg=3).
  2. **`objcopy --globalize-symbol`** — make ~10 blob-internal functions callable from our C.
  3. **`wl_reloc.py`** — rewrite `.rela.text` so the blob's calls to
     `wlc_recv`/`wlc_sendauth`/`wlc_authresp_client` land in our `__wrap_*` hooks.

That's enough to drive SAE frames over the air, inject `wpa_supplicant`'s RSN IE into the
assoc-req, install userspace-derived keys, and add software PMF (drop unprotected deauth;
SW-CCMP answer SA-Queries).

## Reverse engineering

Tools: Ghidra (headless), `nm`, `objdump`, `strings`, a monitor-mode sniffer (`iw` + `tcpdump`).

```sh
# 1. The blob ships inside broadcom-sta and is NOT stripped (~4091 syms) -> Ghidra recovers names.
GHIDRA=/opt/ghidra
$GHIDRA/support/analyzeHeadless ./proj wl -import wlc_hybrid.o_amd64 \
    -analysisTimeoutPerFile 3600          # auto-analyze, then decompile in the GUI

# 2. Triage what's present BEFORE picking a strategy (absent crypto must move host-side):
nm wlc_hybrid.o_amd64 | grep -iE 'sha256|sae|bip|igtk|mmie'          # -> empty here
nm wlc_hybrid.o_amd64 | grep -iE 'wpa|akm|sup|sendauth|key_insert'

# 3. Verify any offset before you patch it (.text vaddr V == file offset V+0x40 in this blob):
objdump -d --start-address=0x47d40 --stop-address=0x47d60 wlc_hybrid.o_amd64
```

Strategy: start at the cfg80211 entry points in the **open** glue (`wl_cfg80211_connect`,
`wl_set_auth_type`) and follow the iovars (`auth`, `wpa_auth`, `wsec`) into the blob. Decompile
what they reach: the AKM gate (`bcmwpa_akm2WPAauth`), the join/auth FSM (`wlc_join_BSS` + the
auth→assoc advancer at `0x5b79d`), the RX dispatch (`wlc_recv`), and the PMK/key path
(`wlc_sup_set_pmk`, `wlc_key_insert`). Cross-check every address with `objdump`.

## Porting to another chip

1. Confirm the blob is a **non-stripped relocatable `.o`** (`file`, `nm`). A stripped firmware
   image won't work this way.
2. In Ghidra find: the **auth-alg clamp**, the **join→auth→assoc FSM** + its "auth-succeeded"
   advancer, the **RX dispatch**, and `set_pmk`/key-insert.
3. Put their addresses in `build.sh` (`--add-symbol re_auth_advance=...`, the globalize list) and
   `patches/wl_reloc.py` (the `__wrap_*` targets).
4. Fix the struct offsets in `wl_linux.c` (`wlc+0x6a8` txq, `bsscfg+0x320` assoc, `scb+0x18` bss)
   — these are layout and **differ per blob version**.
5. Iterate on-air with a sniffer; firmware faults are kernel panics — capture `dmesg` over the
   network (see Struggles).

## Struggles → solutions

- **Kernel hard-locks during SAE, no backtrace.** A `--add-symbol` address was off by one hex
  digit (`0x15b79d` vs `0x5b79d`), landing mid-instruction → `call <garbage>` → NX fault.
  *The tell is the build warning `objtool: ... can't find starting instruction`; verify every
  synthetic symbol is a real function start.*
- **Can't capture the panic.** efi-pstore is broken on Apple EFI; netconsole can't TX over a
  USB-ethernet NIC. *Stream `dmesg --follow` over SSH to a second machine — it flushes the oops
  before the reboot.*
- **AP rejects assoc (status 31, MFP policy).** The blob builds its own PSK/no-MFP RSN IE.
  *Capture `wpa_supplicant`'s `sme->ie` in `.connect` and point the blob's assoc-req IE buffer
  (`*(bsscfg+0x320)+0x30`) at it — also satisfies the 4-way's RSN-IE check.*
- **Key install fails `-22`** — only the IGTK (BIP, idx 4); the HW key engine has no BIP slot.
  *Accept the IGTK in software; PTK/GTK install fine and data flows.*
- **Blob never decrypts management frames**, so 802.11w SA-Queries arrive as ciphertext.
  *Capture the PTK and do AES-CCM in software (kernel `ccm(aes)`) to read the query and emit an
  encrypted response.*

## Build

Needs kernel headers, `gcc`, `binutils`, `python3`. The blob is **not** in this repo (proprietary).

```sh
# 1. Get the pristine blob from broadcom-sta 6.30.223.271:
#    hybrid-v35_64-nodebug-pcoem-6_30_223_271.tar.gz  ->  lib/wlc_hybrid.o_amd64
cp /path/to/wlc_hybrid.o_amd64 wl-src/lib/wlc_hybrid.o_amd64.orig

# 2. Build:
./build.sh                 # -> wl-src/wl.ko   (or download it from Releases)
```

## Install

### Quick test
```sh
sudo rmmod b43 brcmfmac bcma ssb wl 2>/dev/null   # free the card
sudo insmod wl-src/wl.ko                          # wlan0 appears
```
**NetworkManager drives WPA3-SAE through this driver** — just use the wifi GUI: pick your network,
enter the password, done. NM saves it and auto-reconnects on every boot. CLI equivalent:
```sh
nmcli con add type wifi ifname wlan0 con-name w ssid "YOUR_SSID"
nmcli con modify w wifi-sec.key-mgmt sae wifi-sec.psk "YOUR_PASS" 802-11-wireless-security.pmf 3
nmcli con up w        # NM does SAE + 4-way + DHCP
```
(Standalone alternative: `sudo ./examples/connect.sh wlan0 examples/wpa3-sae.conf.example`.)

### Persistent (survives reboot + kernel updates)
```sh
sudo dkms/install.sh
```
Registers the driver with DKMS (auto-rebuilds on kernel upgrades), blacklists the conflicting
in-tree drivers + the stock `wl`, and loads ours at boot before NetworkManager. Then connect from
the wifi GUI. Details and the one DKMS gotcha: [`dkms/README.md`](dkms/README.md). For a one-off
manual rebuild instead, run `./build.sh` → `wl-src/wl.ko`.

### Debug logging
The driver prints verbose WPA3/PMF debug by default. Silence it at runtime (or permanently):
```sh
echo 0 | sudo tee /sys/module/wl/parameters/re_verbose          # this boot
echo 'options wl re_verbose=0' | sudo tee /etc/modprobe.d/wl-quiet.conf   # permanent
```

## Caveats

- **Mixed WPA2/WPA3 (transition-mode) APs are unreliable** — the host-driven SAE doesn't always win
  the negotiation. Use a single mode: set the AP to WPA3-only (or WPA2-only), or pin the security in
  the NetworkManager connection (WPA3 Personal / SAE, or WPA2). A pure-WPA3 network connects every
  time.
- The blob (`wlc_hybrid.o_amd64`) is **Broadcom proprietary** — get it from broadcom-sta yourself.
  The `wl.ko` in Releases embeds it (same situation as Debian's `broadcom-sta-dkms`).
- Offsets are specific to broadcom-sta **6.30.223.271 / BCM4360**.
- Tested on Linux 6.12 (Debian 13), Intel MacBookPro11,3.
- Research code. License: GPL-2.0 (this wrapper) + Broadcom's license (the blob).
