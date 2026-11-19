import { Group, Paper, SegmentedControl, SimpleGrid, Skeleton, Text, ThemeIcon, Tooltip } from '@mantine/core';
import {
  IconAlertTriangle,
  IconArrowsExchange,
  IconBolt,
  IconCloudDownload,
  IconDownload,
  IconUpload,
  type Icon,
} from '@tabler/icons-react';
import type { ReactNode } from 'react';
import type { UsageCounts, UsageRange } from '../../api/client';
import { formatBytes } from '../../lib/format';
import { cacheHitRatio, errorRate, formatCompact, formatPercent, formatRate, USAGE_RANGES } from '../../lib/usage';

export function RangeSelector({ value, onChange }: { value: UsageRange; onChange: (r: UsageRange) => void }) {
  return (
    <SegmentedControl
      size="xs"
      radius="md"
      value={value}
      onChange={(v) => onChange(v as UsageRange)}
      data={USAGE_RANGES.map((r) => ({ value: r.value, label: r.label }))}
      aria-label="Time range"
    />
  );
}

export function StatCard({
  label,
  value,
  sub,
  icon: I,
  color = 'blue',
  help,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon: Icon;
  color?: string;
  help?: string;
}) {
  const card = (
    <Paper p="md" h="100%">
      <Group justify="space-between" align="flex-start" wrap="nowrap" gap="xs">
        <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: 0.4 }}>
          {label}
        </Text>
        <ThemeIcon variant="light" color={color} size={28} radius="md">
          <I size={16} stroke={1.7} />
        </ThemeIcon>
      </Group>
      <Text fw={700} fz={26} lh={1.15} mt={2} style={{ fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>
        {value}
      </Text>
      <Text size="xs" c="dimmed" mt={4} lineClamp={1}>
        {sub ?? ' '}
      </Text>
    </Paper>
  );
  return help ? (
    <Tooltip label={help} withArrow multiline w={260} openDelay={500}>
      <div>{card}</div>
    </Tooltip>
  ) : (
    card
  );
}

/** KPI row: requests (+ current rate), downloads, uploads, data served, cache hit ratio, error rate. */
export function UsageKpis({
  totals,
  requestRate,
  loading,
}: {
  totals?: UsageCounts;
  requestRate?: number;
  loading?: boolean;
}) {
  if (loading || !totals) {
    return (
      <SimpleGrid cols={{ base: 2, sm: 3, lg: 6 }} spacing="sm">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} h={104} radius="md" />
        ))}
      </SimpleGrid>
    );
  }
  const hit = cacheHitRatio(totals);
  const err = errorRate(totals);
  const proxied = totals.cacheHits + totals.cacheMisses;
  return (
    <SimpleGrid cols={{ base: 2, sm: 3, lg: 6 }} spacing="sm">
      <StatCard
        label="Requests"
        value={formatCompact(totals.requests)}
        sub={
          <>
            <IconBolt size={11} style={{ verticalAlign: -1 }} /> {formatRate(requestRate)} now
          </>
        }
        icon={IconArrowsExchange}
        help="All package-client requests in the period. The rate is the average over the last 5 minutes."
      />
      <StatCard
        label="Downloads"
        value={formatCompact(totals.downloads)}
        sub={totals.requests > 0 ? `${formatPercent(totals.downloads / totals.requests)} of requests` : undefined}
        icon={IconDownload}
        color="teal"
      />
      <StatCard
        label="Uploads"
        value={formatCompact(totals.uploads)}
        sub={totals.bytesIn > 0 ? `${formatBytes(totals.bytesIn)} received` : undefined}
        icon={IconUpload}
        color="grape"
      />
      <StatCard
        label="Data served"
        value={formatBytes(totals.bytesOut)}
        sub={totals.downloads > 0 ? `${formatBytes(totals.bytesOut / totals.downloads)} per download` : undefined}
        icon={IconCloudDownload}
        color="cyan"
      />
      <StatCard
        label="Cache hit ratio"
        value={formatPercent(hit)}
        sub={proxied > 0 ? `${formatCompact(totals.cacheHits)} of ${formatCompact(proxied)} proxied` : 'No proxy traffic'}
        icon={IconBolt}
        color="yellow"
        help="Proxy requests answered from the local cache instead of the upstream registry."
      />
      <StatCard
        label="Error rate"
        value={formatPercent(err)}
        sub={totals.errors > 0 ? `${formatCompact(totals.errors)} server errors` : totals.requests > 0 ? 'No server errors' : undefined}
        icon={IconAlertTriangle}
        color={err != null && err >= 0.01 ? 'red' : 'gray'}
        help="Share of requests that failed with a server error (5xx)."
      />
    </SimpleGrid>
  );
}
