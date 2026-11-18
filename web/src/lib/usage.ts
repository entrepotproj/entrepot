import { useCallback, useState } from 'react';
import type { UsageCounts, UsageRange } from '../api/client';
import { formatBytes } from './format';
import { readStored, writeStored } from './storage';

export const USAGE_RANGES: { value: UsageRange; label: string; long: string }[] = [
  { value: '1h', label: '1h', long: 'the last hour' },
  { value: '24h', label: '24h', long: 'the last 24 hours' },
  { value: '7d', label: '7d', long: 'the last 7 days' },
  { value: '30d', label: '30d', long: 'the last 30 days' },
];

const RANGE_KEY = 'entrepot-usage-range';

function isRange(v: string | null): v is UsageRange {
  return USAGE_RANGES.some((r) => r.value === v);
}

/** The selected usage range, remembered across visits. */
export function useUsageRange(): [UsageRange, (r: UsageRange) => void] {
  const [range, setRange] = useState<UsageRange>(() => {
    const v = readStored(RANGE_KEY);
    return isRange(v) ? v : '24h';
  });
  const set = useCallback((r: UsageRange) => {
    setRange(r);
    writeStored(RANGE_KEY, r);
  }, []);
  return [range, set];
}

export function rangeLabel(r: string): string {
  return USAGE_RANGES.find((x) => x.value === r)?.long ?? r;
}

const compactFmt = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 });

/** 1234 -> "1.2K". Below 10,000 the full number is shown. */
export function formatCompact(n: number | undefined | null): string {
  if (n == null || Number.isNaN(n)) return '—';
  return Math.abs(n) < 10_000 ? new Intl.NumberFormat().format(n) : compactFmt.format(n);
}

export function formatPercent(ratio: number | null): string {
  if (ratio == null || Number.isNaN(ratio)) return '—';
  const p = ratio * 100;
  if (p === 0) return '0%';
  if (p < 0.1) return '<0.1%';
  return `${p.toFixed(p >= 99.95 || p < 10 ? 1 : 0).replace(/\.0$/, '')}%`;
}

export function formatRate(perSecond: number | undefined | null): string {
  if (perSecond == null || Number.isNaN(perSecond)) return '—';
  if (perSecond === 0) return '0 req/s';
  if (perSecond < 0.1) return `${(perSecond * 60).toFixed(1).replace(/\.0$/, '')} req/min`;
  return `${perSecond.toFixed(perSecond >= 10 ? 0 : 1)} req/s`;
}

/** hits / (hits + misses), or null when no proxy traffic was seen. */
export function cacheHitRatio(c: UsageCounts): number | null {
  const n = c.cacheHits + c.cacheMisses;
  return n > 0 ? c.cacheHits / n : null;
}

export function errorRate(c: UsageCounts): number | null {
  return c.requests > 0 ? c.errors / c.requests : null;
}

export function isQuiet(c: UsageCounts): boolean {
  return c.requests === 0 && c.downloads === 0 && c.uploads === 0;
}

export { formatBytes };

/** Axis tick label for a bucket start, depending on the bucket size. */
export function tickLabel(t: string, bucketSeconds: number): string {
  const d = new Date(t);
  if (bucketSeconds >= 3 * 3600) {
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

/** Tooltip label: the bucket's start and end. */
export function bucketLabel(t: string, bucketSeconds: number): string {
  const d = new Date(t);
  const end = new Date(d.getTime() + bucketSeconds * 1000);
  const day = (x: Date) => x.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });
  const time = (x: Date) => x.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  if (bucketSeconds >= 3 * 3600) return `${day(d)} ${time(d)} – ${end.toDateString() === d.toDateString() ? '' : day(end) + ' '}${time(end)}`;
  return `${day(d)}, ${time(d)} – ${time(end)}`;
}
