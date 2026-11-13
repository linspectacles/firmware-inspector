# Firmware Inspector

**Expose. Explore. Explain.**

Firmware Inspector is a read-only firmware inspector for platform firmware identity, DMI/SMBIOS, ACPI tables, EFI variables, EFI System Resource Table entries, CPU microcode evidence, Device Tree, and local fwupd device/update state.

Current release: **0.0.5**

Repository: <https://github.com/linspectacles/firmware-inspector>


<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/firmware-inspector.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/firmware-inspector.png"
      alt="Firmware Inspector screenshot"
      width="900"
    >
  </a>
</p>
## What Firmware Inspector is

Firmware Inspector answers a focused question: **what platform-firmware state and firmware-provided system description does the running Linux system expose?**

Version 0.0.5 deepens the existing firmware model with **Microcode** and **Device Tree** while leaving CPU vulnerability assessment and general live hardware topology to their specialist applets.

## Highlights

- Nine categories: **Platform Firmware**, **DMI / SMBIOS**, **ACPI Tables**, **EFI Variables**, **Firmware Update Resources**, **fwupd Devices**, **Update History**, **Microcode**, and **Device Tree**.
- EFI runtime/platform context.
- DMI/SMBIOS identity.
- ACPI static/dynamic table inventory and readable headers.
- EFI variable inventory with scalar Secure Boot-related decoding where exposed.
- ESRT firmware-update resources.
- fwupd device inventory and locally recorded update history.
- CPU microcode loaded-revision evidence plus local Intel/AMD firmware-file evidence.
- Device Tree node hierarchy with safe common-property and raw-property presentation.
- Microcode and Device Tree are lazy and acquired only when selected.
- No automatic privilege escalation.

## Data sources and acquisition

### Core firmware categories

- `/sys/firmware/efi`
- `/sys/class/dmi/id`
- `/sys/firmware/acpi/tables`
- `/sys/firmware/acpi/tables/dynamic`
- `/sys/firmware/efi/efivars`
- `/sys/firmware/efi/esrt/entries`
- `fwupdmgr get-devices --json`
- `fwupdmgr get-history --json`

### Microcode

- `/sys/devices/system/cpu/cpu*/microcode/version`
- `/proc/cpuinfo`
- `/sys/devices/system/cpu/microcode/reload` — presence only; never written.
- `/lib/firmware/intel-ucode`
- `/lib/firmware/amd-ucode`

### Device Tree

- `/sys/firmware/devicetree/base`
- `/proc/device-tree` fallback where exposed.

Platform, DMI/SMBIOS, ACPI, EFI, ESRT, fwupd Devices and Update History are acquired when **Scan** is invoked. **Scan Again** refreshes those plus any lazy category already opened in the session.

Microcode and Device Tree remain lazy.

## Microcode interpretation

Firmware Inspector reports loaded revision evidence and local firmware-file evidence. File presence does not prove a blob was applied or that a newer compatible revision exists.

The runtime reload interface is informational only and is never written.

**CPU Vulnerabilities** remains authoritative for vulnerability/mitigation state.

## Device Tree interpretation

Common properties such as `compatible`, `model`, `status`, `device_type`, and phandle values are decoded where safe. Other properties remain raw evidence with byte-length/appropriate decoded or hex presentation.

A Device Tree `compatible` value is not proof of active driver binding. **Hardware Topology** remains authoritative for live hardware topology.

## Interface

Firmware Inspector uses a category-filtered inventory with Metadata Details. `Ctrl+A` selects All Categories and `Ctrl+1` through `Ctrl+9` select the implemented categories.

## Read-only and scope boundaries

Firmware Inspector does not flash firmware, modify EFI variables/Secure Boot/ACPI state, refresh fwupd remotes, reload microcode, consult online microcode databases, apply Device Tree overlays, or elevate automatically.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| All Categories | `Ctrl+A` |
| Category 1–9 | `Ctrl+1` … `Ctrl+9` |
| Toggle Metadata Details | `F3` |
| Toggle Metadata Details layout | `Ctrl+L` |
| Scan Again / refresh | `Shift+F5` |
| Options | `Ctrl+/` |

## Running from source

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 -m linspectacles_firmware_inspector.standalone
```

`fwupdmgr` is optional and affects only the fwupd categories.

No RPM installation instructions are included in this README.

## LinSpectacles Hub

This applet can run independently, but it can also be installed and used inside **[LinSpectacles Hub](https://github.com/linspectacles/linspectacles-hub)**.

LinSpectacles Hub is the optional workbench for the LinSpectacles applet family. It provides shared applet discovery, navigation and management while each inspector remains independently runnable.

To install a portable or user applet through the Hub, open **Configuration... → Applets** and add the applet ZIP. Once discovered, the applet can be enabled and opened from the Hub navigation.

System-installed applets are discovered by the Hub from its system applet store and remain managed by the system package manager.

## Source layout and LinSpectacles integration

```text
linspectacles_firmware_inspector/
├── __init__.py
├── applet.json
├── standalone.py
├── LICENSE
├── README.md
└── firmware_inspector/
    ├── __init__.py
    ├── applet.py
    ├── _support.py
    └── icon.png
```

## Configuration

Firmware Inspector persists implemented presentation settings only. Those settings do not alter firmware, microcode, EFI or Device Tree state.

## Scope

Firmware Inspector owns **platform firmware interfaces and firmware-provided system-description evidence**. **Boot Loaders** owns boot configuration, **Hardware Topology** owns broader live topology, **CPU Vulnerabilities** owns kernel-reported vulnerability/mitigation state, and **TPM Inspector** owns TPM/PCR/measured-boot evidence.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- LinSpectacles Hub: <https://github.com/linspectacles/linspectacles-hub>
- Repository: <https://github.com/linspectacles/firmware-inspector>
- Issues: <https://github.com/linspectacles/firmware-inspector/issues>

<p align="center">
  <a href="https://github.com/linspectacles/firmware-inspector">
    <img
      src="firmware_inspector/icon.png"
      alt="Firmware Inspector"
      width="256"
    >
  </a>
</p>
