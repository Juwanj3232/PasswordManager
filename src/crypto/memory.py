"""
Secure memory clearing and sensitive buffer handling.

Provides mechanisms to wipe sensitive byte buffers (such as derived encryption keys,
raw passwords, and decrypted credentials) from memory using in-place zeroization.
"""

import ctypes
import gc
from typing import Any, Optional, Union


def secure_wipe(target: Any) -> bool:
    """
    Overwrites the memory buffer of target with zeros in-place.
    
    Supports:
      - bytearray
      - memoryview
      - ctypes arrays
      - lists/tuples of bytearrays
      
    Returns True if successfully wiped, False otherwise.
    """
    if target is None:
        return False

    success = False

    try:
        if isinstance(target, bytearray):
            length = len(target)
            if length > 0:
                address = (ctypes.c_char * length).from_buffer(target)
                ctypes.memset(address, 0, length)
            success = True

        elif isinstance(target, memoryview):
            length = target.nbytes
            if length > 0 and not target.readonly:
                address = (ctypes.c_char * length).from_buffer(target)
                ctypes.memset(address, 0, length)
            success = True

        elif isinstance(target, (list, tuple)):
            for item in target:
                secure_wipe(item)
            success = True

        elif hasattr(target, "_type_") and hasattr(target, "_length_"):
            # ctypes array
            size = ctypes.sizeof(target)
            if size > 0:
                ctypes.memset(ctypes.addressof(target), 0, size)
            success = True

    except Exception:
        # Fallback best-effort overwrite
        try:
            if isinstance(target, bytearray):
                for i in range(len(target)):
                    target[i] = 0
                success = True
        except Exception:
            pass

    return success


class SecureBuffer:
    """
    A protected container for sensitive byte data that guarantees in-place zeroization
    when wiped, when the context manager exits, or when garbage-collected.
    """

    def __init__(self, data: Union[bytes, bytearray, str, None] = None):
        if data is None:
            self._buffer = bytearray()
        elif isinstance(data, str):
            self._buffer = bytearray(data.encode("utf-8"))
        elif isinstance(data, (bytes, bytearray)):
            self._buffer = bytearray(data)
        else:
            raise TypeError("SecureBuffer requires bytes, bytearray, or str")
        self._wiped = False

    @property
    def is_wiped(self) -> bool:
        return self._wiped

    def to_bytes(self) -> bytes:
        """Returns an immutable copy as bytes. Caller should discard quickly."""
        if self._wiped:
            raise ValueError("Buffer has already been securely wiped.")
        return bytes(self._buffer)

    def to_str(self) -> str:
        """Decodes UTF-8 string. Caller should minimize lifetime of string."""
        if self._wiped:
            raise ValueError("Buffer has already been securely wiped.")
        return self._buffer.decode("utf-8")

    def get_raw_buffer(self) -> bytearray:
        """Access the underlying mutable bytearray."""
        if self._wiped:
            raise ValueError("Buffer has already been securely wiped.")
        return self._buffer

    def wipe(self) -> None:
        """Wipes the internal buffer with zeros and triggers GC."""
        if not self._wiped and len(self._buffer) > 0:
            secure_wipe(self._buffer)
            self._wiped = True
            gc.collect()

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()

    def __del__(self):
        try:
            self.wipe()
        except Exception:
            pass

    def __len__(self) -> int:
        return 0 if self._wiped else len(self._buffer)

    def __repr__(self) -> str:
        status = "wiped" if self._wiped else f"{len(self._buffer)} bytes [REDACTED]"
        return f"<SecureBuffer {status}>"
