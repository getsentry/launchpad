from __future__ import annotations

import ctypes

from ctypes.util import find_library
from functools import lru_cache


class CppDemangler:
    def __init__(self) -> None:
        self._demangle = self._load_demangler()
        self._free = self._load_free()

    @staticmethod
    def _load_demangler():
        candidates = [find_library("c++abi"), find_library("stdc++")]
        for candidate in candidates:
            if not candidate:
                continue
            library = ctypes.CDLL(candidate)
            try:
                demangle = getattr(library, "__cxa_demangle")
            except AttributeError:
                continue
            demangle.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            demangle.restype = ctypes.c_void_p
            return demangle
        return None

    @staticmethod
    def _load_free():
        library = ctypes.CDLL(find_library("c") or None)
        free = library.free
        free.argtypes = [ctypes.c_void_p]
        free.restype = None
        return free

    @lru_cache(maxsize=100_000)
    def demangle(self, name: str) -> str | None:
        if self._demangle is None:
            return None
        candidate = name[1:] if name.startswith("__Z") else name
        if not candidate.startswith("_Z"):
            return None
        status = ctypes.c_int()
        result = self._demangle(candidate.encode(), None, None, ctypes.byref(status))
        if not result:
            return None
        try:
            if status.value != 0:
                return None
            return ctypes.string_at(result).decode("utf-8", errors="replace")
        finally:
            self._free(result)
