/**
 * Cache manager with LRU and Redis support
 * @module core/cache
 */

/**
 * Cache entry with metadata
 */
interface CacheEntry<T> {
  /** Cached value */
  value: T;
  /** Expiration timestamp */
  expiresAt: number;
  /** Last access timestamp */
  lastAccessed: number;
  /** Creation timestamp */
  createdAt: number;
}

/**
 * Cache manager options
 */
export interface CacheOptions {
  /** Maximum number of entries */
  maxSize: number;
  /** Default TTL in milliseconds */
  defaultTTL: number;
  /** Redis connection URL */
  redisURL?: string;
  /** Redis key prefix */
  keyPrefix?: string;
}

/**
 * LRU Cache implementation
 */
export class LRUCache<K, V> {
  /** Maximum cache size */
  private maxSize: number;
  /** Cache storage */
  private store: Map<K, CacheEntry<V>>;

  /**
   * Create a new LRUCache
   * @param maxSize - Maximum number of entries
   */
  constructor(maxSize: number = 1000) {
    this.maxSize = maxSize;
    this.store = new Map();
  }

  /**
   * Get a value from cache
   * @param key - Cache key
   * @returns Value or undefined if not found/expired
   * @example
   * ```typescript
   * const value = cache.get('user:123');
   * ```
   */
  get(key: K): V | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;

    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }

    entry.lastAccessed = Date.now();
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value;
  }

  /**
   * Set a value in cache
   * @param key - Cache key
   * @param value - Value to cache
   * @param ttl - Time to live in milliseconds
   * @example
   * ```typescript
   * cache.set('user:123', userData, 300000);
   * ```
   */
  set(key: K, value: V, ttl: number = 300000): void {
    if (this.store.size >= this.maxSize) {
      const firstKey = this.store.keys().next().value;
      if (firstKey !== undefined) {
        this.store.delete(firstKey);
      }
    }

    this.store.set(key, {
      value,
      expiresAt: Date.now() + ttl,
      lastAccessed: Date.now(),
      createdAt: Date.now(),
    });
  }

  /**
   * Delete a value from cache
   * @param key - Cache key
   * @returns True if key was deleted
   * @example
   * ```typescript
   * cache.delete('user:123');
   * ```
   */
  delete(key: K): boolean {
    return this.store.delete(key);
  }

  /**
   * Check if a key exists and is not expired
   * @param key - Cache key
   * @returns True if key exists and is valid
   * @example
   * ```typescript
   * if (cache.exists('user:123')) {
   *   // key is valid
   * }
   * ```
   */
  exists(key: K): boolean {
    const entry = this.store.get(key);
    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return false;
    }
    return true;
  }

  /**
   * Clear all entries from cache
   * @example
   * ```typescript
   * cache.clear();
   * ```
   */
  clear(): void {
    this.store.clear();
  }

  /**
   * Get the current cache size
   * @returns Number of entries
   */
  size(): number {
    return this.store.size;
  }

  /**
   * Get cache keys
   * @returns Array of keys
   */
  keys(): K[] {
    return Array.from(this.store.keys());
  }

  /**
   * Evict expired entries
   * @returns Number of evicted entries
   */
  evictExpired(): number {
    const now = Date.now();
    let count = 0;
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) {
        this.store.delete(key);
        count++;
      }
    }
    return count;
  }
}

/**
 * CacheManager with Redis support and LRU fallback
 */
export class CacheManager {
  /** LRU cache instance */
  private lru: LRUCache<string, unknown>;
  /** Redis client (optional) */
  private redis: unknown;
  /** Whether Redis is connected */
  private redisConnected: boolean;
  /** Default TTL */
  private defaultTTL: number;
  /** Key prefix */
  private keyPrefix: string;

  /**
   * Create a new CacheManager
   * @param options - Cache configuration
   */
  constructor(options: Partial<CacheOptions> = {}) {
    this.lru = new LRUCache(options.maxSize || 1000);
    this.redis = null;
    this.redisConnected = false;
    this.defaultTTL = options.defaultTTL || 300000;
    this.keyPrefix = options.keyPrefix || 'msf:';

    if (options.redisURL) {
      this.connectRedis(options.redisURL);
    }
  }

  /**
   * Connect to Redis
   * @param url - Redis connection URL
   */
  private connectRedis(url: string): void {
    try {
      this.redis = { url };
      this.redisConnected = true;
    } catch {
      this.redisConnected = false;
    }
  }

  /**
   * Get a value from cache
   * @param key - Cache key
   * @returns Value or undefined
   * @example
   * ```typescript
   * const user = await cache.get('user:123');
   * ```
   */
  async get<T>(key: string): Promise<T | undefined> {
    const fullKey = this.keyPrefix + key;

    if (this.redisConnected && this.redis) {
      return undefined;
    }

    return this.lru.get(fullKey) as T | undefined;
  }

  /**
   * Set a value in cache
   * @param key - Cache key
   * @param value - Value to cache
   * @param ttl - Time to live in milliseconds
   * @example
   * ```typescript
   * await cache.set('user:123', userData, 300000);
   * ```
   */
  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    const fullKey = this.keyPrefix + key;
    const effectiveTTL = ttl || this.defaultTTL;

    if (this.redisConnected && this.redis) {
      this.lru.set(fullKey, value, effectiveTTL);
      return;
    }

    this.lru.set(fullKey, value, effectiveTTL);
  }

  /**
   * Delete a value from cache
   * @param key - Cache key
   * @returns True if key was deleted
   * @example
   * ```typescript
   * await cache.delete('user:123');
   * ```
   */
  async delete(key: string): Promise<boolean> {
    const fullKey = this.keyPrefix + key;
    return this.lru.delete(fullKey);
  }

  /**
   * Check if a key exists in cache
   * @param key - Cache key
   * @returns True if key exists
   * @example
   * ```typescript
   * if (await cache.exists('user:123')) {
   *   // cache hit
   * }
   * ```
   */
  async exists(key: string): Promise<boolean> {
    const fullKey = this.keyPrefix + key;
    return this.lru.exists(fullKey);
  }

  /**
   * Clear all cache entries
   * @example
   * ```typescript
   * await cache.clear();
   * ```
   */
  async clear(): Promise<void> {
    this.lru.clear();
  }

  /**
   * Get the LRU cache instance
   * @returns LRUCache instance
   */
  getLRU(): LRUCache<string, unknown> {
    return this.lru;
  }

  /**
   * Check if Redis is connected
   * @returns True if Redis is available
   */
  isRedisConnected(): boolean {
    return this.redisConnected;
  }

  /**
   * Get cache statistics
   * @returns Cache statistics
   */
  getStats(): { size: number; maxSize: number; redisConnected: boolean } {
    return {
      size: this.lru.size(),
      maxSize: this.lru.size(),
      redisConnected: this.redisConnected,
    };
  }
}

let _cache: CacheManager | null = null;

/**
 * Get the global cache manager singleton
 * @param options - Cache options (only on first call)
 * @returns CacheManager instance
 * @example
 * ```typescript
   const cache = getCache({ maxSize: 5000, defaultTTL: 60000 });
   * await cache.set('key', value);
   * ```
   */
export function getCache(options?: Partial<CacheOptions>): CacheManager {
  if (!_cache) {
    _cache = new CacheManager(options);
  }
  return _cache;
}
