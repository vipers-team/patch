# GGnetPatch

A self-contained **runtime** spoofer for the GGnet (NSUS "Iron" / GGPoker) poker
client. It launches `launcher.exe` under its control and feeds the client clean
values whenever it asks the OS for the things it uses to detect a virtual
machine. No shipped file is modified on disk.

> This is a research/testing tool for your own environment. See
> [What it fixes and what it does not](#what-it-fixes-and-what-it-does-not) —
> the hard wall is **server-side**, not in these binaries.

---

## What it does

Three binaries, produced from one C codebase (cross-compiled with mingw-w64):

| File | Arch | Injected into | Purpose |
|---|---|---|---|
| `ggpatch.exe` | x64 | — (the controller) | Launches `launcher.exe`, injects both hooks, coordinates child injection |
| `gghook32.dll` | x86 | `launcher.exe` (32-bit) | Spoofs the launcher's own checks; suspends `GGnet.exe` at spawn |
| `gghook64.dll` | x64 | `GGnet.exe` (64-bit AIR) | Spoofs the AIR runtime + native extensions |

### Hooked and spoofed

| Detection | How it is defeated |
|---|---|
| **Process-name scan** (`vmware`, `vbox`, `qemu`…) | `Process32FirstW/NextW`, `Process32First/Next`, `NtQuerySystemInformation` (SystemProcessInformation) are filtered so VM-named processes are hidden |
| **CPUID hypervisor leaf** (`0x40000000` → `VMwareVMware`/`KVMKVMKVM`) | The `mov eax,0x40000000; cpuid` sites in the main image and `IronANE.dll`/`LockneANE.Windows.dll`/`CppGeoLocs.dll` are patched; a vectored exception handler returns a non-hypervisor result |
| **Debugger present** | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` → `FALSE` |
| **SMBIOS** | `GetSystemFirmwareTable` output is sanitized (VMware/QEMU/innotek/SeaBIOS… → blanked) |
| **MAC address** | `GetAdaptersInfo` / `GetAdaptersAddresses` rewrite known VM OUIs (`00:0C:29`, `08:00:27`, `52:54:00`…) |
| **Registry** | `RegOpenKeyExW` hides VM keys; `RegQueryValueExW` sanitizes VM strings in returned data |
| **Anti-cheat (Loki/Loai)** | optional `--block-loki` rejects `Loki.dll`/`Loai.dll` loads; otherwise the SMBIOS/MAC/registry hooks feed them clean hardware |

The hook engine is a self-written trampoline detour (no MinHook/detours
dependency) with a portable x86/x64 length-disassembler that is unit-tested
(`make test`).

---

## Usage

1. Copy `ggpatch.exe`, `gghook32.dll`, `gghook64.dll` into `bin\` (next to
   `launcher.exe`).
2. Run `ggpatch.exe` (optionally from a console to see its log).

```
ggpatch.exe [bin_dir] [--block-loki] [--no-cpuid]
```

- `bin_dir` — directory containing `launcher.exe`; defaults to the directory
  containing `ggpatch.exe`.
- `--block-loki` — reject `Loki.dll`/`Loai.dll` loads. **Off by default**: the
  server expects Loki heartbeats, so blocking it usually gets you kicked.
- `--no-cpuid` — skip CPUID patching (diagnostics).

The controller prints progress: launcher start, 32-bit injection, then 64-bit
injection when `GGnet.exe` appears.

---

## Building

Requires mingw-w64 (both `i686` and `x86_64`). On macOS: `brew install mingw-w64`.

```
make          # builds ggpatch.exe + gghook32.dll + gghook64.dll into build/
make test     # runs the disassembler unit test on the host
make dist     # packages the binaries + README into dist/ggpatch/
```

The binaries are linked against the Windows Universal CRT (`ucrtbase`), which is
present on Windows 10 and newer.

---

## What it fixes and what it does not

### Fixed locally

- The `"Virtual Machines are prohibited."` / emulator block shown by the
  client-side `checkVirtualMachine` / `CheckProhibitVirtualMachineCommand`
  logic (process names, CPUID, debugger, OBS camera check).

### NOT fixed by this patch (server-side)

The symptom you described on Proxmox — *"starts, then self-terminates after
about 3m45s"* — is the **Loki/Heimdal attestation**, not a local check:

- `IronDesktop.swf` runs `CFLokiHeimdalClient` and sends
  `LOKI_HEIMDAL:CODE_TYPE:HEARTBEAT_CODE` heartbeats.
- `Loki.dll` / `Loai.dll` are **VMProtected** (obfuscated section names, one
  huge mixed text/data section). Their fingerprint is validated **by the
  backend**, so no local patch can forge the response.
- The clean fix for that wall is to make the VM present real-looking hardware at
  the hypervisor level (SMBIOS / MAC / disk serial / CPUID). See
  [`proxmox-hardening.md`](proxmox-hardening.md) for the exact QEMU/Proxmox
  settings.

In short: **the patch defeats the client-side checks; the ~3m45s kill is a
server-side fingerprint problem and is addressed by hardening the VM hardware,
not by these binaries.**

---

## Verification status

- The x86/x64 length-disassembler is covered by a unit test that passes on the
  host (`make test`).
- All three binaries cross-compile cleanly and are the correct architecture
  (PE32 x86 DLL, PE32+ x64 DLL, PE32+ x64 EXE).
- The binaries were **not** executed against the real client from this macOS
  build machine; runtime behaviour on Windows is unverified. Run once with a
  console attached and watch the `[GGnetPatch]` lines.
