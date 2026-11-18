import {
  Anchor,
  Badge,
  Box,
  Button,
  Group,
  Paper,
  Progress,
  SimpleGrid,
  Stack,
  Table,
  Tabs,
  Text,
  ThemeIcon,
  Title,
  Tooltip,
} from '@mantine/core';
import {
  IconAlertTriangle,
  IconChartAreaLine,
  IconCloudDownload,
  IconDatabase,
  IconHourglass,
  IconLock,
  IconPackages,
  IconShieldCheck,
  IconShieldExclamation,
  IconShieldQuestion,
  type Icon,
} from '@tabler/icons-react';
import { useMediaQuery } from '@mantine/hooks';
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import type { BlobStoreSummary, FormatInventory, RepositoryUsage, UsageOverview } from '../../api/client';
import { FormatBadge, FormatIcon, formatLabel, KindBadge } from '../../components/badges';
import { UsageChart, type UsageMetric } from '../../components/usage/UsageChart';
import { formatBytes } from '../../lib/format';
import { formatCompact, rangeLabel } from '../../lib/usage';

export function PanelTitle({
  title,
  description,
  icon: I,
  right,
}: {
  title: string;
  description?: ReactNode;
  icon?: Icon;
  right?: ReactNode;
}) {
  return (
    <Group justify="space-between" align="flex-start" mb="sm" wrap="wrap" gap="sm">
      <Group gap="xs" wrap="nowrap" align="flex-start" style={{ minWidth: 0, flex: '1 1 220px' }}>
        {I && (
          <ThemeIcon variant="light" color="gray" size={26} radius="md" mt={1}>
            <I size={15} stroke={1.7} />
          </ThemeIcon>
        )}
        <div style={{ minWidth: 0 }}>
          <Title order={5} lh={1.3}>
            {title}
          </Title>
          {description && (
            <Text size="xs" c="dimmed">
              {description}
            </Text>
          )}
        </div>
      </Group>
      {right}
    </Group>
  );
}

/** Traffic chart with tabs for requests/downloads and bytes served. */
export function TrafficPanel({ overview }: { overview: UsageOverview }) {
  const [metric, setMetric] = useState<UsageMetric>('traffic');
  return (
    <Paper p="md" h="100%">
      <PanelTitle
        title="Traffic"
        icon={IconChartAreaLine}
        description={`Per ${bucketName(overview.bucketSeconds)}, over ${rangeLabel(overview.range)}`}
        right={
          <Tabs value={metric} onChange={(v) => setMetric((v as UsageMetric) ?? 'traffic')} variant="pills" radius="md">
            <Tabs.List>
              <Tabs.Tab value="traffic" fz="xs" px={10} py={4}>
                Requests
              </Tabs.Tab>
              <Tabs.Tab value="bytes" fz="xs" px={10} py={4}>
                Data served
              </Tabs.Tab>
            </Tabs.List>
          </Tabs>
        }
      />
      <UsageChart series={overview.series} bucketSeconds={overview.bucketSeconds} metric={metric} height={270} />
    </Paper>
  );
}

export function bucketName(seconds: number): string {
  if (seconds % 3600 === 0) return seconds === 3600 ? 'hour' : `${seconds / 3600} hours`;
  if (seconds % 60 === 0) return seconds === 60 ? 'minute' : `${seconds / 60} minutes`;
  return `${seconds} s`;
}

// ---- Security ----

type ScanRow = { key: string; label: string; color: string; icon: Icon; help: string };

const scanRows: ScanRow[] = [
  { key: 'vulnerable', label: 'Vulnerable', color: 'orange', icon: IconShieldExclamation, help: 'Latest scan reported vulnerabilities' },
  { key: 'clean', label: 'Clean', color: 'teal', icon: IconShieldCheck, help: 'No findings at or above the threshold' },
  { key: 'pending', label: 'Pending', color: 'blue', icon: IconHourglass, help: 'A scan is queued or running' },
  { key: 'error', label: 'Scan failed', color: 'gray', icon: IconAlertTriangle, help: 'The last scan failed' },
  { key: 'unscanned', label: 'Not scanned', color: 'gray', icon: IconShieldQuestion, help: 'Not scanned (yet) or unsupported' },
];

export function SecurityPanel({ scan, admin }: { scan: Record<string, number>; admin: boolean }) {
  const n = (k: string) => scan[k] ?? 0;
  const counts: Record<string, number> = {
    vulnerable: n('vulnerable'),
    clean: n('clean'),
    pending: n('pending'),
    error: n('error'),
    unscanned: n('unscanned') + n('unsupported'),
  };
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const quarantined = n('quarantined');
  const scanned = counts.vulnerable + counts.clean;
  return (
    <Paper p="md" h="100%">
      <PanelTitle title="Security" icon={IconShieldCheck} description="Components by latest scan result" />
      {total === 0 ? (
        <Stack align="center" gap={6} py="xl">
          <ThemeIcon size={44} radius="xl" variant="light" color="gray">
            <IconShieldQuestion size={24} stroke={1.5} />
          </ThemeIcon>
          <Text size="sm" fw={600}>
            No components yet
          </Text>
          <Text size="xs" c="dimmed" ta="center" maw={260}>
            Scan results appear once packages are published or cached.
          </Text>
        </Stack>
      ) : (
        <Stack gap="sm">
          <SimpleGrid cols={2} spacing="xs">
            <BigCount
              label="Quarantined"
              value={quarantined}
              color={quarantined > 0 ? 'red' : 'gray'}
              icon={IconLock}
              help="Downloads are blocked until the findings are fixed or waived"
            />
            <BigCount
              label="Vulnerable"
              value={counts.vulnerable}
              color={counts.vulnerable > 0 ? 'orange' : 'gray'}
              icon={IconShieldExclamation}
              help="Components whose latest scan reported vulnerabilities"
            />
          </SimpleGrid>
          <Box>
            <Progress.Root size={10} radius="xl" aria-label="Scan states">
              {scanRows.map((r) =>
                counts[r.key] > 0 ? (
                  <Tooltip key={r.key} label={`${r.label}: ${formatCompact(counts[r.key])}`} withArrow>
                    <Progress.Section value={(counts[r.key] / total) * 100} color={r.key === 'unscanned' ? 'gray.4' : r.color} />
                  </Tooltip>
                ) : null,
              )}
            </Progress.Root>
            <Text size="xs" c="dimmed" mt={6}>
              {scanned > 0
                ? `${Math.round((counts.clean / scanned) * 100)}% of scanned components are clean`
                : 'No component has been scanned yet'}
            </Text>
          </Box>
          <Stack gap={4}>
            {scanRows.map((r) => (
              <Group key={r.key} justify="space-between" wrap="nowrap">
                <Tooltip label={r.help} withArrow openDelay={400} position="left">
                  <Group gap={8} wrap="nowrap">
                    <r.icon size={15} stroke={1.7} color={`var(--mantine-color-${r.color}-6)`} />
                    <Text size="sm">{r.label}</Text>
                  </Group>
                </Tooltip>
                <Text size="sm" fw={600} style={{ fontVariantNumeric: 'tabular-nums' }}>
                  {formatCompact(counts[r.key])}
                </Text>
              </Group>
            ))}
          </Stack>
          <Group gap="xs" mt={4}>
            <Button component={Link} to="/search" size="compact-sm" variant="light">
              Search components
            </Button>
            {admin && (
              <>
                <Button component={Link} to="/admin/scan-jobs" size="compact-sm" variant="default">
                  Scan jobs
                </Button>
                <Button component={Link} to="/admin/waivers" size="compact-sm" variant="default">
                  Waivers
                </Button>
              </>
            )}
          </Group>
        </Stack>
      )}
    </Paper>
  );
}

function BigCount({
  label,
  value,
  color,
  icon: I,
  help,
}: {
  label: string;
  value: number;
  color: string;
  icon: Icon;
  help: string;
}) {
  return (
    <Tooltip label={help} withArrow multiline w={220} openDelay={400}>
      <Paper p="xs" bg={value > 0 ? `var(--mantine-color-${color}-light)` : undefined}>
        <Group gap={6} wrap="nowrap">
          <I size={15} stroke={1.8} color={`var(--mantine-color-${color}-6)`} />
          <Text size="xs" fw={600} c="dimmed" tt="uppercase" style={{ letterSpacing: 0.3 }}>
            {label}
          </Text>
        </Group>
        <Text fw={700} fz={22} lh={1.2} style={{ fontVariantNumeric: 'tabular-nums' }}>
          {formatCompact(value)}
        </Text>
      </Paper>
    </Tooltip>
  );
}

// ---- Top repositories ----

export function TopRepositoriesPanel({ rows, range }: { rows: RepositoryUsage[]; range: string }) {
  const narrow = useMediaQuery('(max-width: 36em)');
  return (
    <Paper p="md" h="100%">
      <PanelTitle title="Top repositories" icon={IconCloudDownload} description={`By requests over ${rangeLabel(range)}`} />
      {rows.length === 0 ? (
        <Text size="sm" c="dimmed" py="lg" ta="center">
          No repository has served requests in this period.
        </Text>
      ) : (
        <Table.ScrollContainer minWidth={narrow ? 0 : 520}>
          <Table verticalSpacing={8} highlightOnHover={false} horizontalSpacing={narrow ? 6 : 'sm'}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Repository</Table.Th>
                {!narrow && <Table.Th>Format</Table.Th>}
                <Table.Th ta="right">Requests</Table.Th>
                {!narrow && <Table.Th ta="right">Downloads</Table.Th>}
                <Table.Th ta="right">Served</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.map((r) => (
                <Table.Tr key={r.repository}>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      {narrow && <FormatIcon format={r.format} size={15} />}
                      <Anchor
                        component={Link}
                        to={`/repositories/${r.repository}/usage`}
                        size="sm"
                        fw={600}
                        style={{ overflowWrap: 'anywhere' }}
                      >
                        {r.repository}
                      </Anchor>
                    </Group>
                  </Table.Td>
                  {!narrow && (
                    <Table.Td>
                      <Group gap={4} wrap="nowrap">
                        <FormatBadge format={r.format} size="sm" style={{ flexShrink: 0 }} />
                        <KindBadge kind={r.kind} size="sm" style={{ flexShrink: 0 }} />
                      </Group>
                    </Table.Td>
                  )}
                  <Table.Td ta="right" style={{ fontVariantNumeric: 'tabular-nums' }}>
                    {formatCompact(r.counts.requests)}
                  </Table.Td>
                  {!narrow && (
                    <Table.Td ta="right" style={{ fontVariantNumeric: 'tabular-nums' }}>
                      {formatCompact(r.counts.downloads)}
                    </Table.Td>
                  )}
                  <Table.Td ta="right" style={{ whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}>
                    {formatBytes(r.counts.bytesOut)}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Paper>
  );
}

// ---- Content inventory ----

export function ContentPanel({ inventory }: { inventory: FormatInventory[] }) {
  const rows = [...inventory].sort((a, b) => b.totalBytes - a.totalBytes || b.repositories - a.repositories);
  const max = Math.max(1, ...rows.map((r) => r.totalBytes));
  const total = rows.reduce(
    (a, r) => ({ repos: a.repos + r.repositories, comps: a.comps + r.components, bytes: a.bytes + r.totalBytes }),
    { repos: 0, comps: 0, bytes: 0 },
  );
  return (
    <Paper p="md" h="100%">
      <PanelTitle
        title="Content"
        icon={IconPackages}
        description={
          rows.length > 0
            ? `${formatCompact(total.repos)} repositories · ${formatCompact(total.comps)} components · ${formatBytes(total.bytes)}`
            : 'Repositories and stored packages per format'
        }
      />
      {rows.length === 0 ? (
        <Text size="sm" c="dimmed" py="lg" ta="center">
          No repositories yet.
        </Text>
      ) : (
        <Table verticalSpacing={8} highlightOnHover={false}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Format</Table.Th>
              <Table.Th ta="right">Repos</Table.Th>
              <Table.Th ta="right">Components</Table.Th>
              <Table.Th ta="right" w="34%">
                Storage
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((r) => (
              <Table.Tr key={r.format}>
                <Table.Td>
                  <Anchor component={Link} to={`/repositories?format=${r.format}`} underline="hover" c="inherit">
                    <Group gap={6} wrap="nowrap">
                      <FormatIcon format={r.format} size={16} />
                      <Text size="sm" fw={500} style={{ whiteSpace: 'nowrap' }}>
                        {formatLabel(r.format)}
                      </Text>
                    </Group>
                  </Anchor>
                </Table.Td>
                <Table.Td ta="right" style={{ fontVariantNumeric: 'tabular-nums' }}>
                  {formatCompact(r.repositories)}
                </Table.Td>
                <Table.Td ta="right" style={{ fontVariantNumeric: 'tabular-nums' }}>
                  <Tooltip label={`${formatCompact(r.assets)} files`} withArrow openDelay={300}>
                    <span>{formatCompact(r.components)}</span>
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  <Stack gap={3} align="stretch">
                    <Text size="sm" ta="right" style={{ whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}>
                      {formatBytes(r.totalBytes)}
                    </Text>
                    <Progress value={(r.totalBytes / max) * 100} size={4} radius="xl" color="blue.7" aria-hidden />
                  </Stack>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </Paper>
  );
}

// ---- Storage (admins) ----

export function StoragePanel({ stores }: { stores: BlobStoreSummary[] }) {
  const total = stores.reduce((a, s) => a + s.totalBytes, 0);
  const sorted = [...stores].sort((a, b) => b.totalBytes - a.totalBytes);
  return (
    <Paper p="md">
      <PanelTitle
        title="Storage"
        icon={IconDatabase}
        description={`${formatBytes(total)} across ${stores.length} blob store${stores.length === 1 ? '' : 's'}`}
        right={
          <Button component={Link} to="/admin/blob-stores" size="compact-sm" variant="subtle">
            Manage
          </Button>
        }
      />
      {sorted.length === 0 ? (
        <Text size="sm" c="dimmed">
          No blob stores configured.
        </Text>
      ) : (
        <SimpleGrid cols={{ base: 1, sm: 2, lg: Math.min(3, sorted.length) }} spacing="md" verticalSpacing="md">
          {sorted.map((s) => (
            <Box key={s.name}>
              <Group justify="space-between" wrap="nowrap" mb={4}>
                <Group gap={6} wrap="nowrap" style={{ minWidth: 0 }}>
                  <Text size="sm" fw={600} truncate="end">
                    {s.name}
                  </Text>
                  <Badge size="xs" variant="default" radius="sm" tt="none">
                    {s.type}
                  </Badge>
                </Group>
                <Text size="sm" fw={600} style={{ whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}>
                  {formatBytes(s.totalBytes)}
                </Text>
              </Group>
              <Progress
                value={total > 0 ? (s.totalBytes / total) * 100 : 0}
                size={8}
                radius="xl"
                color="blue.7"
                aria-label={`${s.name}: ${formatBytes(s.totalBytes)}`}
              />
              <Text size="xs" c="dimmed" mt={4}>
                {total > 0 ? `${Math.round((s.totalBytes / total) * 100)}% · ` : ''}
                {formatCompact(s.blobCount)} blob{s.blobCount === 1 ? '' : 's'} · {s.repositories} repositor
                {s.repositories === 1 ? 'y' : 'ies'}
              </Text>
            </Box>
          ))}
        </SimpleGrid>
      )}
    </Paper>
  );
}
