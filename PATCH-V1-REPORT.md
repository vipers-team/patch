# PATCH V1 — Proxmox/QEMU VM-101 Hardening Report

## Objective

Defeat the **server-side Loki/Heimdal attestation** that causes the GGnet client
running on Proxmox VM **101** (`win10-shared-101`) to start and then
self-terminate after roughly **3m45s**.

`GGnetPatch` defeats the **client-side** VM checks (process names, CPUID,
debugger, SMBIOS, MAC, registry). The ~3m45s kill is a different layer: the
**Loki/Heimdal attestation**. `Loki.dll` / `Loai.dll` are VMProtected and their
device fingerprint is validated **by the backend**, so no process-local patch
can forge the response. The fix is to make the VM present real-looking hardware
at the hypervisor level, verified from inside the guest.

---

## Current config (before hardening)

```text
agent: enabled=1
boot: order=ide1;ide3
ciuser: Administrator
cores: 6
cpu: host,hidden=1,flags=+aes
ide1: local:101/vm-101-disk-0.qcow2,size=150G
ide2: local:101/vm-101-cloudinit.qcow2,media=cdrom,size=4M
ide3: local:iso/virtio-win.iso,media=cdrom,size=856810K
machine: pc-i440fx-10.1
memory: 6145
meta: creation-qemu=10.0.2,ctime=1762539126
name: win10-shared-101
net0: virtio=BC:24:11:8C:F6:1C,bridge=vmbr3,firewall=1
numa: 0
ostype: win10
scsihw: virtio-scsi-single
smbios1: uuid=483582ca-e738-4226-aa11-8fa9cc017e49
sockets: 1
tablet: 1
vmgenid: e1c39deb-7b61-4784-bb80-5a153bcef3bb
```

### Status vs. the hardening guide

| Guide step | Current config | Status |
|---|---|---|
| 1. Hide CPUID leaf | `cpu: host,hidden=1,flags=+aes` | ✅ already done |
| 2. Spoof SMBIOS | only `smbios1: uuid=...` | ⚠️ partial (no vendor/product, no type 0/2/3) |
| 3. Real MAC | `BC:24:11:8C:F6:1C` | ❌ Proxmox/QEMU OUI — must change |
| 4. Disk serial | `ide1: ...size=150G` | ❌ no serial — must add |
| 5. CPU brand / firmware | `cpu: host`; `machine: pc-i440fx-10.1` (SeaBIOS) | CPU brand ✅; firmware only if still detected |

---

## Step-by-step hardening plan

### Step 1 — CPUID (nothing to do)

`cpu: host,hidden=1,flags=+aes` already matches the guide exactly. `hidden=1`
removes the `KVMKVMKVM` hypervisor leaf (leaf `0x40000000` reports "not
present"), and `cpu: host` reports the real host CPU brand string (satisfies
guide step 5.3 too).

### Step 2 — SMBIOS (BIOS / system / baseboard / chassis)

Two things are missing: the **type-1 fields** and the **type-0/2/3 tables**.

`smbios1` maps to QEMU `-smbios type=1`, so do **not** paste the guide's
`args:` line verbatim (it also contains `type=1` — would feed QEMU two type-1
tables). Instead:

1. Extend the existing `smbios1` line (keep the current UUID):

```text
smbios1: uuid=483582ca-e738-4226-aa11-8fa9cc017e49,manufacturer=ASUS,product=System Product Name,version=System Version,serial=S123456789,sku=SKU,family=To be filled by O.E.M.
```

2. Add one `args:` line for the tables Proxmox has no native option for
   (type 0 = BIOS, type 2 = baseboard, type 3 = chassis) — one line, no
   continuation:

```text
args: -smbios type=0,vendor="American Megatrends International, LLC.",version=3801,date=03/11/2022 -smbios type=2,manufacturer="ASUSTeK COMPUTER INC.",product="PRIME X570-PRO",version="Rev X.0x",serial=210798765432109,asset="Default string" -smbios type=3,manufacturer="Default string",version="Default string",serial="Default string",asset="Default string",sku="Default string"
```

**UUID note:** the guide's example UUID `4c4c4544-004a-3410-8033-b7c04f5a3231`
is Dell-style (`4C4C4544` = "LLED"), contradicting an ASUS profile. Keep the
existing v4 UUID `483582ca-...` — stable, consistent with ASUS, and avoids
Windows re-activation.

### Step 3 — MAC address

Change the QEMU OUI `BC:24:11` to a real vendor OUI. **Keep `bridge=vmbr3` and
`firewall=1`** (the guide's example wrongly uses `vmbr0`):

```text
net0: virtio=00:1B:21:3A:4B:5C,bridge=vmbr3,firewall=1
```

`00:1B:21` = Intel. Any real OUI + 3 random bytes works.

**Consistency caveat:** the NIC is `virtio`, seen by the guest as a Red Hat
device (PCI vendor `1AF4`). An Intel MAC on a Red Hat adapter is a mild
mismatch. For full consistency, switch the model to `e1000` (Intel 82540EM,
inbox driver in Win10) and keep the Intel OUI. The guide's approach works as a
first pass; tighten only if still detected.

### Step 4 — Disk serial (and model)

The boot disk is `ide1` (IDE). Proxmox supports `serial=` on IDE drives — no
`args:` needed. Also add `model=` (otherwise an IDE QEMU disk advertises
`QEMU HARDDISK`):

```text
ide1: local:101/vm-101-disk-0.qcow2,size=150G,serial=WD-WX51A8080436,model=WDC_WD1600BEVT-22ZCT0
```

**Size/consistency note:** the disk is 150G, so don't use the guide's
`WD-WCC6Y1PK9A8X` (1TB-class). `WD1600BEVT` is ~160GB-class so serial, model,
and size stay mutually plausible. If the space in `model=` trips the parser,
drop the space (`WDC_WD1600BEVT-22ZCT0`) or set only `serial=`.
`scsihw: virtio-scsi-single` is unrelated to the IDE boot disk and can stay.

---

## Recommended final config (only these lines change)

```text
cpu: host,hidden=1,flags=+aes
smbios1: uuid=483582ca-e738-4226-aa11-8fa9cc017e49,manufacturer=ASUS,product=System Product Name,version=System Version,serial=S123456789,sku=SKU,family=To be filled by O.E.M.
net0: virtio=00:1B:21:3A:4B:5C,bridge=vmbr3,firewall=1
ide1: local:101/vm-101-disk-0.qcow2,size=150G,serial=WD-WX51A8080436,model=WDC_WD1600BEVT-22ZCT0
args: -smbios type=0,vendor="American Megatrends International, LLC.",version=3801,date=03/11/2022 -smbios type=2,manufacturer="ASUSTeK COMPUTER INC.",product="PRIME X570-PRO",version="Rev X.0x",serial=210798765432109,asset="Default string" -smbios type=3,manufacturer="Default string",version="Default string",serial="Default string",asset="Default string",sku="Default string"
```

Everything else (`boot`, `ciuser`, `ide2`/`ide3`, `meta`, `name`, `numa`,
`ostype`, `scsihw`, `sockets`, `tablet`, `vmgenid`) stays exactly as-is.

---

## How to apply

```bash
# 1. Back up first
cp /etc/pve/qemu-server/101.conf /root/101.conf.bak

# 2. Shut the guest down cleanly (inside Windows), or:
qm shutdown 101          # then wait until it's stopped
qm stop 101              # only if shutdown doesn't complete

# 3. Edit the config (nano/vi), paste the lines above
nano /etc/pve/qemu-server/101.conf

# 4. Confirm Proxmox is happy with the config, then start
qm config 101
qm showcmd 101 --pretty | grep -E 'smbios|serial|drive-ide|net0'
qm start 101
```

Do a **full stop/start** (not just a Windows reboot) — the disk `serial` change
is cached by Windows until the QEMU process is restarted.

---

## Verify from inside the guest (PowerShell, as admin)

```powershell
# CPUID / hypervisor leaf — should now be False
(Get-CimInstance Win32_ComputerSystem).HypervisorPresent

# SMBIOS type 0 (BIOS)
Get-CimInstance Win32_BIOS | Select Manufacturer,SMBIOSBIOSVersion,Version,SerialNumber

# SMBIOS type 1 (System)
Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model,SystemFamily,SystemSKUNumber

# SMBIOS type 2 (BaseBoard)
Get-CimInstance Win32_BaseBoard | Select Manufacturer,Product,Version,SerialNumber

# Disk
Get-CimInstance Win32_DiskDrive | Select Model,SerialNumber,Size

# MAC
Get-NetAdapter -Physical | Select Name,MacAddress,InterfaceDescription
```

Expect: no `QEMU`/`SeaBIOS`/`KVM`/`Bochs` anywhere, `HypervisorPresent = False`,
BIOS vendor `American Megatrends...`, system `ASUS`, baseboard
`ASUSTeK ... PRIME X570-PRO`, disk model/serial as set, and the new Intel MAC.

---

## If it still quits after ~3m45s

Follow guide section 5 in order:

1. **ACPI OEM IDs** — QEMU's FADT/DSDT advertise `BOCHS `/`ALASKA`. Override
   with `-acpitable` (extract a real table from physical hardware) or run with
   OVMF (EDK2) UEFI.
2. **Firmware/BIOS type** — currently `pc-i440fx-10.1` (SeaBIOS). Switching to
   OVMF/UEFI (`bios: ovmf`, `machine: q35`, plus an EFI disk) is the strongest
   remaining fix but **invasive** on an installed Windows: requires GPT
   conversion + bootloader re-install. Snapshot first.
3. **CPU brand** — already covered by `cpu: host`.
4. **Clock/`rdtsc`, IO ports, `\\.\` backdoors** — rarely the first thing
   checked; only chase if 1–3 don't clear it.

---

## Caveats

- **Windows activation:** changing the SMBIOS *UUID* forces reactivation — keep
  `483582ca-...`. Changing only string fields (manufacturer/product/serial) does
  not change machine identity.
- **Consistency is the whole game:** attestation compares many fields — keep
  vendor/MAC/model/serial/size mutually plausible. Inconsistent spoofing is
  itself a detectable fingerprint.
- **New NIC identity:** changing the MAC makes Windows treat the adapter as new
  (new connection profile, possibly new IP on DHCP). Re-check the GGnet access
  path after the change.
- **Backup/snapshot before starting**, especially before any OVMF conversion.

---

## Verification status

- Advisory plan produced for VM **101**; `.conf` edits are applied on the
  Proxmox host by the operator, not in this workspace.
- Nothing was executed against the real client from this machine; runtime
  behaviour on Windows remains unverified until the operator applies the config
  and runs the in-guest PowerShell checks above.
