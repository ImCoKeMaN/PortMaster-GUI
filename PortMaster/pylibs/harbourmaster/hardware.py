# SPDX-License-Identifier: MIT
# ==============================================================================
# PortMaster Hardware Provider (Env-backed Dynamic Loader with Fallback)
# ==============================================================================
from __future__ import annotations

import copy
import math
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


def _safe_int(val: Any, default: int = 0) -> int:
    """Safely converts values to int, returning default on failure or empty string."""
    if val is None:
        return default
    try:
        val_str = str(val).strip()
        return int(val_str) if val_str else default
    except (ValueError, TypeError):
        return default


def _read_env(env_path: Path) -> Dict[str, str]:
    """Reads key-value pairs from a POSIX shell env file."""
    res = {}
    if not env_path.is_file():
        return res
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                res[k.strip().lower()] = v.strip("\"' \r\n")
    except Exception:
        pass
    return res


def _normalize_glibc(raw: str) -> str:
    raw = str(raw).strip()
    if "." in raw or not raw.isdigit():
        return raw
    if len(raw) == 3:
        return f"{raw[0]}.{raw[1:]}"
    return raw


def _find_control_dir() -> Path:
    if os.environ.get("controlfolder"):
        return Path(os.environ["controlfolder"])
    if os.environ.get("PORTMASTER_HOME"):
        return Path(os.environ["PORTMASTER_HOME"])

    file_path = Path(__file__).resolve()
    for p in file_path.parents:
        if (p / "device_info.env").is_file() or (p / "version").is_file() or p.name.lower() == "portmaster":
            return p
    if len(file_path.parents) >= 3:
        return file_path.parents[2]
    return file_path.parent


def _build_capabilities(info: Dict[str, Any], raw_env: Dict[str, str]) -> List[str]:
    """Generates the full HarbourMaster capability array if missing from env."""
    caps: List[str] = []

    # 1. Architecture
    arch = str(info.get("primary_arch", "aarch64")).lower()
    caps.append(arch)
    if raw_env.get("device_has_armhf") == "Y" or arch == "armhf":
        caps.append("armhf")
    if raw_env.get("device_has_aarch64") == "Y" or arch == "aarch64":
        caps.append("aarch64")
    if raw_env.get("device_has_x86") == "Y" or arch == "x86":
        caps.append("x86")
    if raw_env.get("device_has_x86_64") == "Y" or arch == "x86_64":
        caps.append("x86_64")

    # 2. CFW & Device Slugs
    cfw = str(info.get("name", "unknown")).lower()
    dev = str(info.get("device", "unknown")).lower()
    model = str(info.get("model", "")).lower()
    for item in (cfw, dev, model):
        if item and item != "unknown":
            caps.append(item)

    # 3. Dynamic OpenGL & Vulkan
    gl_markers = [
        "/usr/lib/libGL.so",
        "/usr/lib/libGL.so.1",
        "/usr/lib/aarch64-linux-gnu/libGL.so.1",
        "/usr/lib/arm-linux-gnueabihf/libGL.so.1",
        "/usr/lib/x86_64-linux-gnu/libGL.so.1",
        ]
    if raw_env.get("has_desktop_gl") == "Y" or any(os.path.exists(p) for p in gl_markers):
        caps.append("opengl")
    if raw_env.get("has_vulkan") == "Y" or os.path.exists("/usr/lib/libvulkan.so.1"):
        caps.append("vulkan")

    # 4. CPU Power & Ultra
    cpu = str(info.get("cpu", "")).lower()
    ram_mb = _safe_int(info.get("ram", 1024), 1024)
    ram_gb = ram_mb // 1024

    # 'power': enabled on all devices EXCEPT rk3326 and px30
    if not any(low_c in cpu for low_c in ["rk3326", "px30"]):
        caps.append("power")

    # 'ultra': requires >= 4GB RAM AND excludes budget SoCs
    low_power_cpus = [
        "rk3326",
        "h700",
        "a133",
        "a133plus",
        "a527",
        "px30",
        "sun50iw9",
        "sun50iw10",
        ]
    if ram_gb >= 4 and not any(lpc in cpu for lpc in low_power_cpus):
        caps.append("ultra")

    # 5. Display Dimensions & Aspect Ratio
    res = info.get("resolution", (640, 480))
    w = _safe_int(res[0] if isinstance(res, (tuple, list)) and len(res) > 0 else 640, 640)
    h = _safe_int(res[1] if isinstance(res, (tuple, list)) and len(res) > 1 else 480, 480)
    caps.append(f"{w}x{h}")

    gcd = math.gcd(w, h) if h != 0 else 1
    ax, ay = w // gcd, h // gcd
    if ax == 8 and ay == 5:
        ax, ay = 16, 10
    caps.append(f"{ax}:{ay}")
    if f"{ax}:{ay}" == "16:10":
        caps.append("16:9")

    if w >= 960 or h >= 720:
        caps.append("hires")
    elif w < 640 or h < 480:
        caps.append("lowres")

    if (w / h) >= 1.5 if h != 0 else False:
        caps.append("wide")
    elif ax == ay:
        caps.append("square")

    # 6. Analog Controller Sticks & Triggers
    sticks = _safe_int(info.get("analogsticks", 0), 0)
    for i in range(sticks + 1):
        caps.append(f"analog_{i}")
    if info.get("analogtriggers") == "Y":
        caps.append("analog_triggers")

    # 7. Cumulative RAM tags
    for tier in (1, 2, 4, 8, 16, 32):
        if ram_gb >= tier:
            caps.append(f"{tier}gb")

    # 8. Restore
    caps.append("restore")

    # Deduplicate preserving order
    seen = set()
    return [c for c in caps if not (c in seen or seen.add(c))]


class HardwareDetector:
    """Consumes dynamic hardware and OS capabilities from device_info.env."""

    def __init__(self, control_dir: Optional[Union[str, Path]] = None):
        self.control_dir = Path(control_dir) if control_dir else _find_control_dir()

    def _locate_env_file(self) -> Optional[Path]:
        search_dirs = [
            self.control_dir,
            Path.cwd(),
            Path("/userdata/system/.local/share/PortMaster"),
            Path("/userdata/system/.local/share"),
            Path("/roms/tools/PortMaster"),
            Path("/roms2/tools/PortMaster"),
            Path("/storage/roms/tools/PortMaster"),
            Path("/mnt/SDCARD/App/PortMaster"),
            Path("/opt/muos"),
            ]

        # 1. Exact match for device_info.env
        for d in search_dirs:
            p = d / "device_info.env"
            if p.is_file():
                return p

        # 2. Glob match for named device_info_*.env
        for d in search_dirs:
            if d.is_dir():
                named = list(d.glob("device_info_*.env"))
                if named:
                    return named[0]

        # 3. Trigger bash generation if script is available
        sh_script = self.control_dir / "device_info.txt"
        if sh_script.is_file():
            try:
                subprocess.run(["bash", str(sh_script)], timeout=3, check=False)
                p = self.control_dir / "device_info.env"
                if p.is_file():
                    return p
            except Exception:
                pass

        return None

    def get_info(self, force_refresh: bool = False) -> Dict[str, Any]:
        env_file = self._locate_env_file()
        raw_env = _read_env(env_file) if env_file else {}

        def get_val(key: str, default: Any) -> Any:
            val = raw_env.get(key, os.environ.get(key.upper(), default))
            if val is None or (isinstance(val, str) and not val.strip()):
                return default
            return val

        w = _safe_int(get_val("display_width", 640), 640)
        h = _safe_int(get_val("display_height", 480), 480)

        # Handle device RAM fallback
        ram_mb_val = get_val("device_ram_mb", None)
        if ram_mb_val is not None:
            ram_mb = _safe_int(ram_mb_val, 1024)
        else:
            ram_mb = _safe_int(get_val("device_ram", 1), 1) * 1024

        sticks = _safe_int(get_val("analog_sticks", 2), 2)
        cfw = str(get_val("cfw_name", "Unknown")).lower()
        dev_slug = str(get_val("device_slug", get_val("device_name", "unknown"))).lower()

        info: Dict[str, Any] = {
            "name": cfw,
            "version": str(get_val("cfw_version", "Unknown")),
            "device": dev_slug,
            "model": str(get_val("device_name", "Unknown")),
            "resolution": (w, h),
            "analogsticks": sticks,
            "analogtriggers": str(get_val("analog_triggers", "N")),
            "cpu": str(get_val("device_cpu", "Unknown")),
            "primary_arch": str(get_val("device_arch", "aarch64")),
            "ram": ram_mb,
            "glibc": _normalize_glibc(get_val("cfw_glibc", "Unknown")),
            }

        caps_raw = str(get_val("device_capabilities", "")).strip()
        if caps_raw:
            info["capabilities"] = caps_raw.split()
        else:
            info["capabilities"] = _build_capabilities(info, raw_env)

        return info


# ==============================================================================
# HarbourMaster & Pugwash API Endpoints and Compatibility Shims
# ==============================================================================
HW_INFO: Dict[str, Any] = {}
DEVICES: Dict[str, Any] = {}


def device_info(config: Any = None) -> Dict[str, Any]:
    return HardwareDetector().get_info()


def hardware_info() -> Dict[str, Any]:
    return HardwareDetector().get_info()


def find_device_by_resolution(resolution: Tuple[int, int]) -> str:
    info = HardwareDetector().get_info()
    if info.get("resolution") == resolution:
        return info.get("device", "default")
    return "default"


def expand_info(
    info: Dict[str, Any],
    override_resolution: Optional[Tuple[int, int]] = None,
    override_ram: Optional[int] = None,
    use_old_cpu_info: bool = False,
    ) -> Dict[str, Any]:
    base_info = HardwareDetector().get_info()
    if not isinstance(info, dict):
        info = copy.deepcopy(base_info)
    else:
        for k, v in base_info.items():
            info.setdefault(k, v)

    if override_resolution:
        w, h = override_resolution
        info["resolution"] = (w, h)
        caps = [c for c in info.get("capabilities", []) if not ("x" in c and c.replace("x", "").isdigit())]
        caps.append(f"{w}x{h}")
        info["capabilities"] = caps

    if override_ram:
        info["ram"] = override_ram

    return info


__all__ = [
    "device_info",
    "hardware_info",
    "expand_info",
    "find_device_by_resolution",
    "DEVICES",
    "HW_INFO",
    ]
