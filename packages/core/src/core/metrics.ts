/**
 * Metrics registry for collecting and exposing application metrics
 * @module core/metrics
 */

/**
 * Metric type enumeration
 */
export enum MetricType {
  /** Monotonically increasing counter */
  COUNTER = 'counter',
  /** Distribution of values */
  HISTOGRAM = 'histogram',
  /** Point-in-time value */
  GAUGE = 'gauge',
}

/**
 * Counter metric for monotonically increasing values
 */
export interface CounterMetric {
  /** Metric name */
  name: string;
  /** Metric description */
  description: string;
  /** Current value */
  value: number;
  /** Metric labels */
  labels: Record<string, string>;
}

/**
 * Histogram metric for value distributions
 */
export interface HistogramMetric {
  /** Metric name */
  name: string;
  /** Metric description */
  description: string;
  /** Bucket boundaries */
  buckets: number[];
  /** Bucket counts */
  bucketCounts: number[];
  /** Sum of all observed values */
  sum: number;
  /** Total count of observations */
  count: number;
  /** Metric labels */
  labels: Record<string, string>;
}

/**
 * Gauge metric for point-in-time values
 */
export interface GaugeMetric {
  /** Metric name */
  name: string;
  /** Metric description */
  description: string;
  /** Current value */
  value: number;
  /** Metric labels */
  labels: Record<string, string>;
}

/**
 * Metrics registry for managing counters, histograms, and gauges
 */
export class MetricsRegistry {
  /** Counter metrics storage */
  private counters: Map<string, CounterMetric>;
  /** Histogram metrics storage */
  private histograms: Map<string, HistogramMetric>;
  /** Gauge metrics storage */
  private gauges: Map<string, GaugeMetric>;

  /**
   * Create a new MetricsRegistry
   */
  constructor() {
    this.counters = new Map();
    this.histograms = new Map();
    this.gauges = new Map();
  }

  /**
   * Register a new counter metric
   * @param name - Metric name
   * @param description - Metric description
   * @param labels - Optional labels
   * @example
   * ```typescript
   * registry.registerCounter('http_requests_total', 'Total HTTP requests', { method: 'GET' });
   * ```
   */
  registerCounter(name: string, description: string, labels: Record<string, string> = {}): void {
    this.counters.set(name, { name, description, value: 0, labels });
  }

  /**
   * Register a new histogram metric
   * @param name - Metric name
   * @param description - Metric description
   * @param buckets - Bucket boundaries
   * @param labels - Optional labels
   * @example
   * ```typescript
   * registry.registerHistogram('http_request_duration_ms', 'Request duration', [5, 10, 25, 50, 100, 250, 500, 1000]);
   * ```
   */
  registerHistogram(
    name: string,
    description: string,
    buckets: number[] = [5, 10, 25, 50, 100, 250, 500, 1000],
    labels: Record<string, string> = {}
  ): void {
    this.histograms.set(name, {
      name,
      description,
      buckets,
      bucketCounts: new Array(buckets.length + 1).fill(0),
      sum: 0,
      count: 0,
      labels,
    });
  }

  /**
   * Register a new gauge metric
   * @param name - Metric name
   * @param description - Metric description
   * @param labels - Optional labels
   * @example
   * ```typescript
   * registry.registerGauge('active_connections', 'Current active connections');
   * ```
   */
  registerGauge(name: string, description: string, labels: Record<string, string> = {}): void {
    this.gauges.set(name, { name, description, value: 0, labels });
  }

  /**
   * Increment a counter by the specified amount
   * @param name - Counter name
   * @param value - Amount to increment (default 1)
   * @example
   * ```typescript
   * registry.incCounter('http_requests_total');
   * registry.incCounter('http_requests_total', 5);
   * ```
   */
  incCounter(name: string, value: number = 1): void {
    const counter = this.counters.get(name);
    if (!counter) {
      this.registerCounter(name, name);
      this.counters.get(name)!.value += value;
      return;
    }
    counter.value += value;
  }

  /**
   * Observe a value in a histogram
   * @param name - Histogram name
   * @param value - Value to observe
   * @example
   * ```typescript
   * registry.observeHistogram('http_request_duration_ms', 42);
   * ```
   */
  observeHistogram(name: string, value: number): void {
    const histogram = this.histograms.get(name);
    if (!histogram) {
      this.registerHistogram(name, name);
      this.observeHistogram(name, value);
      return;
    }
    histogram.sum += value;
    histogram.count += 1;
    for (let i = 0; i < histogram.buckets.length; i++) {
      if (value <= histogram.buckets[i]) {
        histogram.bucketCounts[i] += 1;
        return;
      }
    }
    histogram.bucketCounts[histogram.bucketCounts.length - 1] += 1;
  }

  /**
   * Set a gauge to an absolute value
   * @param name - Gauge name
   * @param value - Value to set
   * @example
   * ```typescript
   * registry.setGauge('active_connections', 42);
   * ```
   */
  setGauge(name: string, value: number): void {
    const gauge = this.gauges.get(name);
    if (!gauge) {
      this.registerGauge(name, name);
      this.gauges.get(name)!.value = value;
      return;
    }
    gauge.value = value;
  }

  /** Alias for setGauge */
  gauge(name: string, value: number, labels?: Record<string, string>): void {
    if (labels) {
      this.registerGauge(name, name, labels);
    }
    this.setGauge(name, value);
  }

  /**
   * Increment a gauge by the specified amount
   * @param name - Gauge name
   * @param value - Amount to increment (default 1)
   * @example
   * ```typescript
   * registry.incGauge('active_connections');
   * ```
   */
  incGauge(name: string, value: number = 1): void {
    const gauge = this.gauges.get(name);
    if (!gauge) {
      this.registerGauge(name, name);
      this.gauges.get(name)!.value += value;
      return;
    }
    gauge.value += value;
  }

  /**
   * Decrement a gauge by the specified amount
   * @param name - Gauge name
   * @param value - Amount to decrement (default 1)
   * @example
   * ```typescript
   * registry.decGauge('active_connections');
   * ```
   */
  decGauge(name: string, value: number = 1): void {
    const gauge = this.gauges.get(name);
    if (!gauge) {
      this.registerGauge(name, name);
      this.gauges.get(name)!.value -= value;
      return;
    }
    gauge.value -= value;
  }

  /**
   * Get all metrics in a structured format
   * @returns Object containing all metric types
   * @example
   * ```typescript
   * const metrics = registry.getMetrics();
   * console.log(metrics.counters, metrics.histograms, metrics.gauges);
   * ```
   */
  getMetrics(): {
    counters: Map<string, CounterMetric>;
    histograms: Map<string, HistogramMetric>;
    gauges: Map<string, GaugeMetric>;
  } {
    return {
      counters: new Map(this.counters),
      histograms: new Map(this.histograms),
      gauges: new Map(this.gauges),
    };
  }

  /**
   * Start a timer for measuring duration
   * @param name - Histogram metric name
   * @returns Object with stop() method
   */
  startTimer(name: string): { stop(): void } {
    const start = Date.now();
    return {
      stop: () => {
        const duration = Date.now() - start;
        this.observeHistogram(name, duration);
      },
    };
  }

  /**
   * Clear all metrics
   */
  clear(): void {
    this.counters.clear();
    this.histograms.clear();
    this.gauges.clear();
  }
}

let _metrics: MetricsRegistry | null = null;

/**
 * Get the global metrics registry singleton
 * @returns MetricsRegistry instance
 * @example
 * ```typescript
   const metrics = getMetrics();
   * metrics.incCounter('requests_total');
   * ```
   */
export function getMetrics(): MetricsRegistry {
  if (!_metrics) {
    _metrics = new MetricsRegistry();
  }
  return _metrics;
}
