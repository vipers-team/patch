# Proxmox / QEMU hardening — fixing the ~3m45s self-termination

`GGnetPatch` defeats the **client-side** VM checks. The symptom you see on
Proxmox (the client starts, then quits after roughly 3 minutes 45 seconds) is a
different layer: the **Loki/Heimdal attestation**. `Loki.dll`/`Loai.dll` are
VMProtected and their device fingerprint is validated **by the backend**, so no
process-local patch can fake the response.

The fix is to make the VM present real-looking hardware at the hypervisor level.
Everything below is applied on the Proxmox host to the game VM, then verified
from inside the guest.

---

## 1. Hide the hypervisor CPUID leaf

`IronANE.dll` and `launcher.exe` read CPUID leaf `0x40000000` and match
`VMwareVMware` / `KVMKVMKVM` / `Microsoft Hv` etc. On Proxmox/KVM that leaf
returns `KVMKVMKVM`.

In `/etc/pve/qemu-server/<vmid>.conf` set the CPU type with the `hidden` flag:

```
cpu: host,hidden=1,flags=+aes
```

`hidden=1` removes the hypervisor leaf so leaf `0x40000000` reports "not
present". Keep `+aes` (and any other flags you use) or Proxmox may complain.

Reboot the VM, then confirm with a CPUID tool inside the guest (CPU-Z, or
PowerShell): the vendor at `0x40000000` should be empty, and `KVM` should not
appear.

## 2. Spoof SMBIOS (BIOS / system / board)

`Loki` and the client's `HardwareInformation.as` read DMI/SMBIOS (via WMI
`Win32_BIOS` / `Win32_ComputerSystem` / `Win32_BaseBoard`, which read the real
SMBIOS). QEMU's defaults advertise `SeaBIOS`, `QEMU`, or `Bochs`.

Append raw `-smbios` arguments with an `args:` line:

```
args: -smbios type=0,vendor="American Megatrends International, LLC.",version=3801,date="03/11/2022" -smbios type=1,manufacturer="ASUS",product="System Product Name",version="System Version",serial="S123456789",uuid=4c4c4544-004a-3410-8033-b7c04f5a3231,sku="SKU",family="To be filled by O.E.M." -smbios type=2,manufacturer="ASUSTeK COMPUTER INC.",product="PRIME X570-PRO",version="Rev X.0x",serial="210798765432109",asset="Default string" -smbios type=3,manufacturer="Default string",version="Default string",serial="Default string",asset="Default string",sku="Default string"
```

Use a `uuid` that looks like a real SMBIOS UUID (the one above is a plausible
Dell-style UUID; replace it with your own stable value). After a reboot,
`dmidecode` inside the guest should show your values and no `QEMU`/`SeaBIOS`.

## 3. Use a real-looking MAC address

The VM NIC MAC is the most visible fingerprint. Proxmox defaults to the QEMU OUI
`BC:24:11` / `52:54:00`. Set a real vendor OUI (here, an Intel NIC) on the NIC:

```
net0: virtio=00:1B:21:3A:4B:5C,bridge=vmbr0
```

Pick an OUI matching a common NIC vendor (Intel `00:1B:21`, Realtek
`00:E0:4C`, etc.) and a random remaining 3 bytes.

## 4. Give disks realistic serial numbers

`Loki` commonly reads disk serials (WMI `Win32_DiskDrive` →
`SerialNumber`). A QEMU/virtio disk advertises `QM00001` / `drive-*`. Add a
`serial=` to each disk:

```
scsi0: local-lvm:vm-100-disk-0,size=64G,serial=WD-WCC6Y1PK9A8X
```

(For SATA/IDE drives use the equivalent `serial=` on the drive line; for virtio
add `serial=` too.) Verify with `wmic diskdrive get model,serialnumber`.

## 5. If it is still detected after 3m45s

These are the next layers to check, in order:

1. **ACPI OEM IDs** — QEMU's FADT/DSDT advertise `BOCHS `/`ALASKA`. If Loki
   reads ACPI tables, override them with `-acpitable` (extract a real table
   from physical hardware and load it), or run with OVMF (EDK2) UEFI which uses
   different OEM IDs.
2. **Firmware/BIOS type** — prefer OVMF UEFI over SeaBIOS; some checks flag the
   SeaBIOS payload.
3. **CPU brand/vendor string** — use `cpu: host` (not `qemu64`) so the guest
   reports a genuine CPU model rather than `QEMU Virtual CPU`.
4. **Clock/`rdtsc`, IO ports, `\\.\` backdoors** — only relevant if the above
   don't clear it; these are rarely the first thing checked.

## Why the patch can't do this part

`Loki.dll`/`Loai.dll` are packed (randomized section names, a single ~48 MB
mixed text/data section). Their fingerprint is recomputed and validated
server-side as part of the `LOKI_HEIMDAL:HEARTBEAT_CODE` exchange. A local
runtime hook can sanitize the standard APIs they read (which `GGnetPatch` does),
but it cannot forge a server-side attestation — only making the hardware look
real (the steps above) does that.
