import { Center, Skeleton, Stack, Text, ThemeIcon } from '@mantine/core';
import { IconChartAreaLine } from '@tabler/icons-react';
import { lazy, Suspense } from 'react';
import type { UsagePoint } from '../../api/client';
import type { UsageMetric } from './UsageChartImpl';

// Recharts is ~100 kB gzipped: load it only where a chart is shown.
const UsageChartImpl = lazy(() => import('./UsageChartImpl'));

export type { UsageMetric };

/** Requests/downloads (or bytes served) over time, with an empty state when there was no traffic. */
export function UsageChart({
  series,
  bucketSeconds,
  metric = 'traffic',
  height = 260,
  emptyHint,
}: {
  series: UsagePoint[];
  bucketSeconds: number;
  metric?: UsageMetric;
  height?: number;
  emptyHint?: string;
}) {
  const hasTraffic = (pts: UsagePoint[]) =>
    pts.some((p) => (metric === 'bytes' ? p.bytesOut > 0 : p.requests > 0 || p.downloads > 0));
  // The newest bucket is still filling up; plotting it would show a misleading
  // drop at the right edge. The totals above still include it. Keep it when it
  // holds all the traffic (a 15-minute bucket on the 24h range often does):
  // dropping it would report "no traffic" while the totals show some.
  const last = series[series.length - 1];
  if (last && new Date(last.t).getTime() + bucketSeconds * 1000 > Date.now() && series.length > 1) {
    const settled = series.slice(0, -1);
    if (hasTraffic(settled)) series = settled;
  }
  const empty = !hasTraffic(series);
  if (empty) {
    return (
      <Center h={height}>
        <Stack align="center" gap={6}>
          <ThemeIcon size={44} radius="xl" variant="light" color="gray">
            <IconChartAreaLine size={24} stroke={1.5} />
          </ThemeIcon>
          <Text fw={600} size="sm">
            No traffic in this period yet
          </Text>
          <Text size="xs" c="dimmed" ta="center" maw={320}>
            {emptyHint ?? 'Requests appear here a few seconds after clients use a repository.'}
          </Text>
        </Stack>
      </Center>
    );
  }
  return (
    <Suspense fallback={<Skeleton h={height} radius="md" />}>
      <UsageChartImpl series={series} bucketSeconds={bucketSeconds} metric={metric} height={height} />
    </Suspense>
  );
}
