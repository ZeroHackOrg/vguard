# src/vguard/bloom.py
import hashlib
import math


class BloomFilter:
    def __init__(self, capacity: int = 100_000, error_rate: float = 0.001):
        if not (0 < error_rate < 1):
            raise ValueError("error_rate must be in (0, 1)")
        self.capacity = int(capacity)
        self.error_rate = error_rate
        self.bit_count = max(8, -int((self.capacity * math.log(self.error_rate)) / (math.log(2) ** 2)))
        self.hash_count = max(1, int((self.bit_count / self.capacity) * math.log(2)))
        self.bits = bytearray((self.bit_count + 7) // 8)
        self.inserted = 0

    def _hashes(self, item: str):
        digest = hashlib.sha256(item.encode("utf-8")).digest()
        d1, d2 = digest[:16], digest[16:]
        for i in range(self.hash_count):
            combined = hashlib.sha256(d1 + i.to_bytes(4, "big") + d2).digest()
            yield int.from_bytes(combined[:8], "big") % self.bit_count

    def add(self, item: str) -> None:
        for bit in self._hashes(item):
            self.bits[bit >> 3] |= 1 << (bit & 7)
        self.inserted += 1

    def contains(self, item: str) -> bool:
        for bit in self._hashes(item):
            if not (self.bits[bit >> 3] & (1 << (bit & 7))):
                return False
        return True

    def __contains__(self, item: str) -> bool:
        return self.contains(item)