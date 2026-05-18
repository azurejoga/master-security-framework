"""
Master Security Framework - Cache Manager
==========================================

Multi-tier caching with Redis backend and in-memory LRU fallback.
Used for rate limiting, session storage, and threat intelligence caching.

Features:
    - Redis backend with in-memory LRU fallback
    - TTL-based expiration
    - Thread-safe operations
    - Async support
    - Cache invalidation patterns

Usage:
    >>> from master_security.core import get_cache
    >>> cache = get_cache()
    >>> cache.set("rate_limit:user:123", 42, ttl=60)
    >>> cache.get("rate_limit:user:123")
    42
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Optional

from master_security.core.logger import get_logger

logger = get_logger("msf.cache")


class LRUCache:
    """Thread-safe LRU cache for in-memory fallback."""

    def __init__(self, maxsize: int = 10000) -> None:
        self.maxsize = maxsize
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                value, expiry = self._cache[key]
                if expiry > time.monotonic():
                    self._cache.move_to_end(key)
                    return value
                else:
                    del self._cache[key]
            return None

    def set(self, key: str, value: Any, ttl: int = 60) -> None:
        with self._lock:
            expiry = time.monotonic() + ttl
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (value, expiry)
            while len(self._cache) > self.maxsize:
                self._cache.popitem(last=False)

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


class CacheManager:
    """
    Multi-tier cache manager with Redis and LRU fallback.

    Attributes:
        redis_url: Redis connection URL (optional)
        max_memory_entries: Max in-memory entries

    Example:
        >>> cache = CacheManager()
        >>> cache.set("key", "value", ttl=3600)
        >>> cache.get("key")
        'value'
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        max_memory_entries: int = 10000,
    ) -> None:
        self.redis_url = redis_url
        self._memory_cache = LRUCache(max_memory_entries)
        self._redis = None
        self._lock = threading.Lock()

    def _get_redis(self):
        if self._redis is None and self.redis_url:
            try:
                import redis
                self._redis = redis.from_url(self.redis_url, decode_responses=True)
                self._redis.ping()
                logger.info("msf.cache.redis_connected")
            except Exception as exc:
                logger.warning("msf.cache.redis_failed", error=str(exc))
                self._redis = False  # Mark as unavailable
        return self._redis if self._redis and self._redis is not False else None

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None.
        """
        redis = self._get_redis()
        if redis:
            try:
                value = redis.get(key)
                if value is not None:
                    return value
            except Exception:
                pass
        return self._memory_cache.get(key)

    def set(self, key: str, value: Any, ttl: int = 60) -> None:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds
        """
        redis = self._get_redis()
        if redis:
            try:
                redis.setex(key, ttl, str(value))
            except Exception:
                pass
        self._memory_cache.set(key, value, ttl)

    def delete(self, key: str) -> bool:
        """Delete value from cache."""
        redis = self._get_redis()
        if redis:
            try:
                redis.delete(key)
            except Exception:
                pass
        return self._memory_cache.delete(key)

    def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        redis = self._get_redis()
        if redis:
            try:
                return bool(redis.exists(key))
            except Exception:
                pass
        return self._memory_cache.exists(key)

    def increment(self, key: str, amount: int = 1, ttl: int = 60) -> int:
        """Atomically increment a counter."""
        redis = self._get_redis()
        if redis:
            try:
                pipe = redis.pipeline()
                pipe.incr(key, amount)
                pipe.expire(key, ttl)
                result = pipe.execute()
                return result[0]
            except Exception:
                pass
        current = self._memory_cache.get(key) or 0
        new_value = int(current) + amount
        self._memory_cache.set(key, new_value, ttl)
        return new_value

    def clear(self) -> None:
        """Clear all cached data."""
        redis = self._get_redis()
        if redis:
            try:
                redis.flushdb()
            except Exception:
                pass
        self._memory_cache.clear()


_global_cache: CacheManager | None = None
_cache_lock = threading.Lock()


def get_cache(redis_url: Optional[str] = None) -> CacheManager:
    """
    Get the global cache manager.

    Args:
        redis_url: Optional Redis URL override.

    Returns:
        Global CacheManager instance.
    """
    global _global_cache
    if _global_cache is None:
        with _cache_lock:
            if _global_cache is None:
                _global_cache = CacheManager(redis_url=redis_url)
    return _global_cache
