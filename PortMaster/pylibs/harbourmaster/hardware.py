#!/usr/bin/env python3
# ==============================================================================
# PortMaster Dynamic Hardware & CFW Detection Engine (v2)
# ==============================================================================
# Dynamic hardware detection replacing legacy hardcoded lookup tables.
# Provides 100% schema and value parity with Harbourmaster and PortMaster bash.
# ==============================================================================

import glob
import math
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


def _read_file(path: str | Path, single_line: bool = True) -> str:
    """Safely reads text content from a file without throwing exceptions."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            if single_line:
                return f.readline().strip("\0\r\n ")
            return f.read()
    except Exception:
        return ""


def _calc_gcd(a: int, b: int) -> int:
    """Calculates the greatest common divisor for aspect ratio reduction."""
    return math.gcd(a, b) if b != 0 else a


def _normalize_glibc(raw: str) -> str:
    """Ensures GLIBC is formatted with dotted notation (e.g. 241 -> 2.41)."""
    raw = str(raw).strip()
    if "." in raw:
        return raw
    if len(raw) == 3 and raw.isdigit():
        return f"{raw[0]}.{raw[1:]}"
    return raw


class HardwareDetector:
    """Probes host hardware, CFW distribution, screen geometry, SoC, and memory."""

    def __init__(self, control_dir: Optional[str | Path] = None):
        if control_dir:
            self.control_dir = Path(control_dir)
        elif os.environ.get("controlfolder"):
            self.control_dir = Path(os.environ["controlfolder"])
        elif os.environ.get("PORTMASTER_HOME"):
            self.control_dir = Path(os.environ["PORTMASTER_HOME"])
        else:
            self.control_dir = Path(__file__).resolve().parents[2]

        self.info: Dict[str, Any] = {}

    def load_env_cache(self, env_path: Optional[Path] = None) -> bool:
        """Loads cached properties from device_info.env if present and valid."""
        target = env_path or (self.control_dir / "device_info.env")
        if not target.is_file():
            return False

        content = _read_file(target, single_line=False)
        if not content:
            return False

        parsed: Dict[str, Any] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            val = val.strip("\"' \r\n")
            key_lower = key.strip().lower()

            if key_lower in (
                "device_ram",
                "display_width",
                "display_height",
                "display_orientation",
                "aspect_x",
                "aspect_y",
                "analog_sticks",
            ):
                try:
                    parsed[key_lower] = int(val)
                except ValueError:
                    parsed[key_lower] = 0
            elif key_lower == "cfw_glibc":
                parsed[key_lower] = _normalize_glibc(val)
            else:
                parsed[key_lower] = val

        if parsed.get("device_name") and parsed.get("cfw_name"):
            self.info = parsed
            return True
        return False

    def detect_all(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Runs the complete dynamic hardware probe or loads from env cache."""
        if not force_refresh and self.load_env_cache():
            return self.info

        self.info = {
            "device_info_version": "0.3.0",
            "pm_version": self._detect_pm_version(),
            "cfw_name": "Unknown",
            "cfw_version": "Unknown",
            "cfw_glibc": "Unknown",
            "device_name": "Unknown",
            "device_cpu": "Unknown",
            "device_arch": "unknown",
            "device_ram": 1,
            "device_has_armhf": "N",
            "device_has_aarch64": "N",
            "device_has_x86": "N",
            "device_has_x86_64": "N",
            "display_width": 640,
            "display_height": 480,
            "display_orientation": 0,
            "aspect_x": 4,
            "aspect_y": 3,
            "analog_sticks": 2,
        }

        self._detect_architecture()
        self._detect_cfw()
        self._detect_glibc()
        self._detect_hardware()
        self._detect_display()
        self._detect_controls()

        return self.info

    # --------------------------------------------------------------------------
    # Sub-Detectors
    # --------------------------------------------------------------------------
    def _detect_pm_version(self) -> str:
        v_file = self.control_dir / "version"
        if v_file.is_file():
            return _read_file(v_file) or "Unknown"
        return os.environ.get("PM_VERSION", "Unknown")

    def _detect_architecture(self):
        raw_arch = platform.machine().lower()
        if raw_arch in ("aarch64", "arm64"):
            self.info["device_arch"] = "aarch64"
            self.info["device_has_aarch64"] = "Y"
            armhf_markers = [
                "/lib/arm-linux-gnueabihf",
                "/usr/lib/arm-linux-gnueabihf",
                "/lib32",
                "/usr/lib32",
                "/lib/ld-linux-armhf.so.3",
            ]
            if any(os.path.exists(p) for p in armhf_markers):
                self.info["device_has_armhf"] = "Y"

        elif raw_arch.startswith("armv7") or raw_arch in ("armhf", "armv8l"):
            self.info["device_arch"] = "armhf"
            self.info["device_has_armhf"] = "Y"

        elif raw_arch in ("x86_64", "amd64"):
            self.info["device_arch"] = "x86_64"
            self.info["device_has_x86_64"] = "Y"
            x86_markers = [
                "/lib/i386-linux-gnu",
                "/usr/lib/i386-linux-gnu",
                "/usr/lib32",
                "/lib/ld-linux.so.2",
            ]
            if any(os.path.exists(p) for p in x86_markers):
                self.info["device_has_x86"] = "Y"

        elif re.match(r"i[3-6]86|x86", raw_arch):
            self.info["device_arch"] = "x86"
            self.info["device_has_x86"] = "Y"
        else:
            self.info["device_arch"] = raw_arch

    def _detect_cfw(self):
        # 1. RetroDECK Flatpak
        if (
            os.path.exists("/app/bin/retrodeck")
            or os.environ.get("FLATPAK_ID") == "net.retrodeck.retrodeck"
        ):
            self.info["cfw_name"] = "RetroDECK"
            cfg = _read_file("/var/config/retrodeck/retrodeck.cfg", False)
            match = re.search(r'version\s*=\s*"?([^\s"\r\n]+)', cfg, re.I)
            if match:
                self.info["cfw_version"] = match.group(1)
            return

        # 2. ROCKNIX & JELOS
        if (
            os.path.exists("/etc/rocknix-release")
            or os.path.exists("/storage/.config/rocknix")
            or "rocknix"
            in _read_file("/etc/os-release", False)
            + _read_file("/usr/lib/os-release", False)
        ):
            self.info["cfw_name"] = "ROCKNIX"
            if os.path.exists("/etc/rocknix-release"):
                self.info["cfw_version"] = _read_file("/etc/rocknix-release")
            return

        if (
            os.path.exists("/etc/jelos-release")
            or os.path.exists("/storage/.config/jelos")
            or "jelos"
            in _read_file("/etc/os-release", False)
            + _read_file("/usr/lib/os-release", False)
        ):
            self.info["cfw_name"] = "JELOS"
            if os.path.exists("/etc/jelos-release"):
                self.info["cfw_version"] = _read_file("/etc/jelos-release")
            return

        # 3. muOS
        if (
            os.path.exists("/opt/muos/config/system/version")
            or os.path.exists("/opt/muos/config/version.txt")
            or os.path.isdir("/opt/muos")
        ):
            self.info["cfw_name"] = "muOS"
            v = _read_file("/opt/muos/config/system/version") or _read_file(
                "/opt/muos/config/version.txt"
            )
            if v:
                self.info["cfw_version"] = v
            return

        # 4. Plymouth theme (ArkOS, dArkOS, TheRA)
        plymouth_text = _read_file(
            "/usr/share/plymouth/themes/text.plymouth", False
        )
        if plymouth_text:
            match = re.search(r"title=(.*)", plymouth_text, re.I)
            if match:
                title = match.group(1).strip()
                if "darkos" in title.lower():
                    self.info["cfw_name"] = "dArkOS"
                elif "thera" in title.lower():
                    self.info["cfw_name"] = "TheRA"
                elif "arkos" in title.lower():
                    self.info["cfw_name"] = "ArkOS"

                ver_m = re.search(r"\b(20[2-3][0-9]{5,6}|\d{6,8})\b", title)
                if ver_m:
                    self.info["cfw_version"] = ver_m.group(1)
                return

        # 5. Knulli
        if (
            os.path.exists("/boot/boot/knulli.board")
            or os.path.exists("/boot/knulli.board")
            or os.path.exists("/etc/knulli.version")
            or "knulli" in _read_file("/etc/os-release", False).lower()
        ):
            self.info["cfw_name"] = "knulli"
            for kpath in [
                "/etc/knulli.version",
                "/boot/knulli.version",
                "/userdata/system/knulli.version",
                "/etc/knulli_version",
            ]:
                if os.path.exists(kpath):
                    self.info["cfw_version"] = _read_file(kpath)
                    break
            if (
                self.info["cfw_version"] == "Unknown"
                and os.path.exists("/etc/os-release")
            ):
                m_kver = re.search(
                    r'^OS_VERSION="?([^"\r\n]+)',
                    _read_file("/etc/os-release", False),
                    re.MULTILINE,
                )
                if m_kver:
                    self.info["cfw_version"] = m_kver.group(1)
            if self.info["cfw_version"] == "Unknown":
                self.info["cfw_version"] = "scarab"
            return

        # 6. Batocera / AmberELEC / RetroOZ
        if os.path.exists("/usr/share/batocera/batocera.version"):
            self.info["cfw_name"] = "Batocera.linux"
            self.info["cfw_version"] = _read_file(
                "/usr/share/batocera/batocera.version"
            )
            return

        # 7. Generic /etc/os-release Fallback
        for os_file in ["/etc/os-release", "/usr/lib/os-release"]:
            if os.path.exists(os_file):
                data = _read_file(os_file, False)
                m_name = re.search(
                    r'^(?:NAME|ID)="?([^"\r\n]+)', data, re.MULTILINE
                )
                m_ver = re.search(
                    r'^(?:VERSION_ID|VERSION)="?([^"\r\n]+)', data, re.MULTILINE
                )
                if m_name:
                    self.info["cfw_name"] = m_name.group(1)
                if m_ver:
                    self.info["cfw_version"] = m_ver.group(1)
                break

    def _detect_glibc(self):
        # 1. Inspect runtime libc shared object directly
        for libc_path in [
            "/lib/libc.so.6",
            "/lib64/libc.so.6",
            "/usr/lib/libc.so.6",
            "/usr/lib64/libc.so.6",
            "/lib/aarch64-linux-gnu/libc.so.6",
            "/lib/arm-linux-gnueabihf/libc.so.6",
            "/lib/x86_64-linux-gnu/libc.so.6",
        ]:
            if os.path.exists(libc_path):
                try:
                    res = subprocess.run(
                        [libc_path], capture_output=True, text=True, timeout=1
                    )
                    m = re.search(r"version (\d+\.\d+)", res.stdout)
                    if m:
                        self.info["cfw_glibc"] = _normalize_glibc(m.group(1))
                        return
                except Exception:
                    pass

                real = os.path.realpath(libc_path)
                m = re.search(r"libc[.-](\d+\.\d+)", real)
                if m:
                    self.info["cfw_glibc"] = _normalize_glibc(m.group(1))
                    return

        # 2. getconf fallback
        try:
            res = subprocess.run(
                ["getconf", "GNU_LIBC_VERSION"],
                capture_output=True,
                text=True,
                timeout=1,
            )
            m = re.search(r"(\d+\.\d+)", res.stdout)
            if m:
                self.info["cfw_glibc"] = _normalize_glibc(m.group(1))
        except Exception:
            pass

    def _detect_hardware(self):
        # 1. Board files & CFW markers
        board_candidates = [
            "/opt/muos/device/config/board/name",
            "/opt/muos/config/device.txt",
            "/boot/boot/knulli.board",
            "/boot/knulli.board",
            "/userdata/system/knulli.board",
            "/boot/boot/batocera.board",
            "/boot/batocera.board",
            "/var/run/batocera.board",
            "/userdata/system/batocera.board",
            "/etc/batocera.board",
            Path.home() / ".config/.CUSTOM_DEVICE",
            Path.home() / ".config/.DEVICE",
            "/userdata/system/.DEVICE",
            "/userdata/system/.CUSTOM_DEVICE",
            "/etc/device_model",
            "/etc/board",
        ]
        for candidate in board_candidates:
            if os.path.exists(candidate):
                name = _read_file(candidate)
                if name:
                    self.info["device_name"] = name
                    break

        # DMI Fallback for x86 Handhelds
        if (
            self.info["device_name"] == "Unknown"
            and os.path.exists("/sys/devices/virtual/dmi/id/product_name")
        ):
            dmi = _read_file("/sys/devices/virtual/dmi/id/product_name")
            dmi_map = {
                "Galileo": "Steam Deck OLED",
                "Jupiter": "Steam Deck",
                "RC71L": "ROG Ally",
                "83E1": "Legion Go",
                "G1618-04": "GPD Win 4",
                "G1617-01": "GPD Win Mini",
            }
            self.info["device_name"] = dmi_map.get(dmi, dmi)

        # Device Tree Model Fallback
        if self.info["device_name"] == "Unknown":
            for dt_path in [
                "/proc/device-tree/model",
                "/sys/firmware/devicetree/base/model",
            ]:
                if os.path.exists(dt_path):
                    self.info["device_name"] = _read_file(dt_path)
                    break

        # 2. CPU / SoC Resolution
        compatible = (
            _read_file("/proc/device-tree/compatible", False)
            + _read_file("/sys/firmware/devicetree/base/compatible", False)
        ).lower()
        dev_name = self.info["device_name"].lower()
        cpuinfo = _read_file("/proc/cpuinfo", False)
        cpuinfo_lower = cpuinfo.lower()

        # Check DT / Compatible / Device Name first
        if (
            "a133" in compatible
            or "sun50iw10" in compatible
            or "trimui-smart-pro" in dev_name
            or "trimui-brick" in dev_name
        ):
            self.info["device_cpu"] = "a133plus"
        elif (
            "sun50iw9" in compatible
            or "h700" in compatible
            or re.match(r"^(rg35xx|rg28xx|rg40xx|rgcubexx|rg34xx)", dev_name)
        ):
            self.info["device_cpu"] = "h700"
        elif "rk3588" in compatible or "rk3588" in cpuinfo_lower:
            self.info["device_cpu"] = "rk3588"
        elif (
            "rk3566" in compatible
            or "rk3568" in compatible
            or "rk3566" in cpuinfo_lower
        ):
            self.info["device_cpu"] = "rk3566"
        elif (
            "rk3326" in compatible
            or "px30" in compatible
            or "rk3326" in cpuinfo_lower
            or any(
                x in dev_name
                for x in [
                    "g350",
                    "rg351",
                    "rgb10",
                    "rgb20",
                    "rk2020",
                    "rk2023",
                    "r33s",
                    "r35s",
                    "r36s",
                    "xu10",
                ]
            )
        ):
            self.info["device_cpu"] = "rk3326"
        elif "sm8550" in compatible or "sm8550" in cpuinfo_lower:
            self.info["device_cpu"] = "SM8550"
        elif "sm8450" in compatible or "sm8450" in cpuinfo_lower:
            self.info["device_cpu"] = "SM8450"
        elif "sm8250" in compatible or "sm8250" in cpuinfo_lower:
            self.info["device_cpu"] = "SM8250"

        # MIDR Part Code Fallback for BSP kernels
        if self.info["device_cpu"] == "Unknown":
          cpuinfo = _read_file("/proc/cpuinfo", False)
          m_part = re.search(r"CPU part\s*:\s*0x([0-9a-fA-F]+)", cpuinfo)
          if m_part:
            part_code = "0x" + m_part.group(1).lower()
            if part_code == "0xd04":  # Cortex-A35 -> RK3326
              self.info["device_cpu"] = "rk3326"
            elif part_code == "0xd05":  # Cortex-A55 -> RK3566 or H700
              if "allwinner" in cpuinfo.lower() or "sun50i" in cpuinfo.lower():
                self.info["device_cpu"] = "h700"
              else:
                self.info["device_cpu"] = "rk3566"
            elif part_code == "0xd03":  # Cortex-A53 -> A133+
              self.info["device_cpu"] = "a133plus"

        if self.info["device_cpu"] == "Unknown":
            self.info["device_cpu"] = self.info["device_arch"]

        # 3. RAM (Ceiled to physical GB capacity)
        meminfo = _read_file("/proc/meminfo", False)
        mem_match = re.search(r"MemTotal:\s+(\d+)\s+kB", meminfo)
        if mem_match:
            kb = int(mem_match.group(1))
            self.info["device_ram"] = (kb + 1048575) // 1048576

    def _detect_display(self):
        for mode_file in glob.glob("/sys/class/drm/card*-*/modes"):
            status_file = Path(mode_file).parent / "status"
            if (
                os.path.exists(status_file)
                and "connected" in _read_file(status_file)
            ):
                first_mode = _read_file(mode_file)
                m = re.match(r"^(\d+)x(\d+)", first_mode)
                if m:
                    self.info["display_width"] = int(m.group(1))
                    self.info["display_height"] = int(m.group(2))
                    break

        if (
            self.info["display_width"] == 640
            and self.info["display_height"] == 480
        ):
            fb_modes = _read_file("/sys/class/graphics/fb0/modes")
            m = re.search(r"(\d+)x(\d+)", fb_modes)
            if m:
                self.info["display_width"] = int(m.group(1))
                self.info["display_height"] = int(m.group(2))

        dev_name = self.info["device_name"]
        if any(
            x in dev_name for x in ["Steam Deck", "ROG Ally", "Legion Go", "GPD"]
        ):
            if self.info["display_width"] < self.info["display_height"]:
                self.info["display_width"], self.info["display_height"] = (
                    self.info["display_height"],
                    self.info["display_width"],
                )

        w, h = self.info["display_width"], self.info["display_height"]
        gcd = _calc_gcd(w, h)
        if gcd > 0:
            ax, ay = w // gcd, h // gcd
            if ax == 8 and ay == 5:
                ax, ay = 16, 10
            self.info["aspect_x"] = ax
            self.info["aspect_y"] = ay
    

    def _detect_controls(self):
        name = self.info["device_name"].upper()
        if any(
            k in name
            for k in [
                "RG35XX-PLUS",
                "RG35XX-SP",
                "RG28XX",
                "RG35XX-2024",
                "RG34XX",
                "MIYOO MINI",
                "TRIMUI-BRICK",
            ]
        ):
            self.info["analog_sticks"] = 0
        elif any(k in name for k in ["RG351V", "RGB20S", "RG40XX-V"]):
            self.info["analog_sticks"] = 1
        else:
            self.info["analog_sticks"] = 2

    # --------------------------------------------------------------------------
    # Output Schema Exporters
    # --------------------------------------------------------------------------
    def to_harbourmaster_dict(self) -> Dict[str, Any]:
        """Outputs 100% compliant Harbourmaster dictionary format."""
        info = self.detect_all()
        w, h = info["display_width"], info["display_height"]
        ax, ay = info["aspect_x"], info["aspect_y"]
        ram_mb = info["device_ram"] * 1024

        capabilities: List[str] = ["opengl", "power"]

        # Multi-lib tags (in Harbourmaster order: armhf, aarch64)
        if info["device_has_armhf"] == "Y":
            capabilities.append("armhf")
        if info["device_has_aarch64"] == "Y":
            capabilities.append("aarch64")
        if info["device_has_x86"] == "Y":
            capabilities.append("x86")
        if info["device_has_x86_64"] == "Y":
            capabilities.append("x86_64")

        # CFW specific features
        if info["cfw_name"].lower() in ("arkos", "darkos", "muos", "thera", "rocknix", "jelos", "steamos", "retrodeck", "batocera.linux", "knulli" ):
            capabilities.append("restore")

        # Display and device tags
        capabilities.extend(
            [
                f"{ax}:{ay}",
                f"{w}x{h}",
                info["cfw_name"].lower(),
                info["device_name"].lower(),
            ]
        )
        if f"{ax}:{ay}" == "16:10":
            capabilities.append("16:9")
            
        for i in range(info["analog_sticks"] + 1):
            capabilities.append(f"analog_{i}")

        if w >= 960 or h >= 720:
            capabilities.append("hires")
        elif w < 640 or h < 480:
            capabilities.append("lowres")

        if (w / h) >= 1.5 or w >= 854:
            capabilities.append("wide")
        
        # Cumulative RAM tiers
        ram_gb = info["device_ram"]
        for tier in (1, 2, 4, 8, 16, 32):
            if ram_gb >= tier:
                capabilities.append(f"{tier}gb")

        if info["device_ram"] >= 4:
            capabilities.append("ultra")

        return {
            "name": info["cfw_name"].lower(),
            "version": info["cfw_version"],
            "device": info["device_name"].lower(),
            "resolution": (w, h),
            "analogsticks": info["analog_sticks"],
            "cpu": info["device_cpu"],
            "capabilities": capabilities,
            "primary_arch": info["device_arch"],
            "ram": ram_mb,
            "glibc": _normalize_glibc(info["cfw_glibc"]),
        }

# Compatibility API Endpoints
def hardware_info() -> Dict[str, Any]:
    """Returns the ENV/Bash dictionary format."""
    return HardwareDetector().detect_all()


def device_info(config: Any = None) -> Dict[str, Any]:
    """Direct drop-in replacement for harbourmaster.platform.device_info()"""
    return HardwareDetector().to_harbourmaster_dict()


if __name__ == "__main__":
    import json

    print(json.dumps(device_info(), indent=2))

# ==============================================================================
# Legacy Compatibility Shims for PortMaster / Harbourmaster v1 API
# ==============================================================================
import copy

HW_INFO = {}
DEVICES = {}


def find_device_by_resolution(resolution):
  """Legacy shim for finding a device by (width, height) tuple."""
  det = HardwareDetector()
  res_dict = det.to_harbourmaster_dict()
  if res_dict.get('resolution') == resolution:
    return res_dict.get('device', 'default')
  return 'default'


def expand_info(
    info, override_resolution=None, override_ram=None, use_old_cpu_info=False
):
  """Legacy shim for expanding dictionary info in-place."""
  det = HardwareDetector()
  if isinstance(info, dict):
    det.info = copy.deepcopy(info)
  merged = det.to_harbourmaster_dict()
  if isinstance(info, dict):
    info.update(merged)
  return info