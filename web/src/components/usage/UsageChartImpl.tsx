import '@mantine/charts/styles.css';

import { AreaChart, ChartTooltip, type AreaChartSeries } from '@mantine/charts';
import { useMemo } from 'react';
import type { UsagePoint } from '../../api/client';
import { formatBytes } from '../../lib/format';
import { bucketLabel, formatCompact, tickLabel } from '../../lib/usage';

export type UsageMetric = 'traffic' | 'bytes';

// Series colors: blue.7 / teal.7 pass lightness, chroma, CVD and contrast
// checks on both the light and the dark surface.
const trafficSeries: AreaChartSeries[] = [
  { name: 'requests', label: 'Requests', color: 'blue.7' },
  { name: 'downloads', label: 'Downloads', color: 'teal.7' },
];
const bytesSeries: AreaChartSeries[] = [{ name: 'bytesOut', label: 'Data served', color: 'blue.7' }];

const KiB = 1024;
const NICE = [1, 2, 2.5, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000];

/** Y-axis ticks for byte values at round binary units (0, 2 GB, 4 GB, …) instead of raw-byte "nice" numbers. */
function byteTicks(max: number): number[] | undefined {
  if (max <= 0) return undefined;
  let unit = 1;
  while (max / unit >= KiB && unit < KiB ** 5) unit *= KiB;
  const m = max / unit;
  const step = NICE.find((n) => m / n <= 4) ?? 1000;
  const top = Math.ceil(m / step) * step;
  const ticks: number[] = [];
  for (let v = 0; v <= top + 1e-9; v += step) ticks.push(v * unit);
  return ticks;
}

export default function UsageChartImpl({
  series,
  bucketSeconds,
  metric,
  height,
}: {
  series: UsagePoint[];
  bucketSeconds: number;
  metric: UsageMetric;
  height: number;
}) {
  const bytes = metric === 'bytes';
  const fmt = bytes ? (v: number) => formatBytes(v) : (v: number) => formatCompact(v);
  const data = useMemo(() => series.map((p) => ({ ...p })), [series]);
  const ticks = useMemo(() => (bytes ? byteTicks(Math.max(...series.map((p) => p.bytesOut))) : undefined), [bytes, series]);
  return (
    <AreaChart
      h={height}
      data={data}
      dataKey="t"
      series={bytes ? bytesSeries : trafficSeries}
      curveType="monotone"
      strokeWidth={2}
      fillOpacity={0.18}
      withDots={false}
      withLegend={!bytes}
      legendProps={{ verticalAlign: 'top', height: 36 }}
      gridAxis="y"
      strokeDasharray="3 3"
      tickLine="none"
      valueFormatter={fmt}
      yAxisProps={{
        width: bytes ? 72 : 48,
        allowDecimals: false,
        ...(ticks ? { ticks, domain: [0, ticks[ticks.length - 1]], interval: 0 } : {}),
      }}
      xAxisProps={{ tickFormatter: (t: string) => tickLabel(t, bucketSeconds), minTickGap: 32 }}
      tooltipAnimationDuration={120}
      tooltipProps={{
        content: ({ label, payload }) => (
          <ChartTooltip
            label={label ? bucketLabel(String(label), bucketSeconds) : ''}
            payload={payload as never}
            series={bytes ? bytesSeries : trafficSeries}
            valueFormatter={fmt}
          />
        ),
      }}
    />
  );
}
