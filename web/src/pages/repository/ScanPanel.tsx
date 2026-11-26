import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Chip,
  Group,
  Paper,
  ScrollArea,
  Skeleton,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  Title,
  Tooltip,
} from '@mantine/core';
import {
  IconAlertTriangle,
  IconExternalLink,
  IconLock,
  IconRadar2,
  IconShieldCheck,
  IconShieldOff,
} from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import {
  api,
  ApiError,
  unwrap,
  type Component,
  type ComponentScans,
  type Finding,
  type Repository,
  type ScanResult,
  type SeverityCounts,
  type WaiverInput,
} from '../../api/client';
import { qk2, useComponentScans } from '../../api/queries';
import { JobStatusBadge, ScanStateBadge, SEVERITIES, severityColor, SeverityBadge } from '../../components/badges';
import { QueryError } from '../../components/states';
import { WaiverModal } from '../../components/WaiverModal';
import { useAuth } from '../../lib/auth';
import { formatDate, formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

function sumCounts(results: ScanResult[]): SeverityCounts {
  const c: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const r of results) for (const s of SEVERITIES) c[s] += r.counts?.[s] ?? 0;
  return c;
}

export function SeverityCountsView({ counts, size = 'md' }: { counts: SeverityCounts; size?: 'sm' | 'md' }) {
  return (
    <Group gap={6} wrap="wrap">
      {SEVERITIES.map((s) => (
        <Tooltip key={s} label={`${counts[s]} ${s}`} withArrow>
          <Badge
            size={size === 'sm' ? 'sm' : 'lg'}
            radius="sm"
            variant={counts[s] > 0 ? 'filled' : 'light'}
            color={counts[s] > 0 ? severityColor(s) : 'gray'}
            tt="none"
            styles={{ root: { minWidth: size === 'sm' ? 0 : 74 } }}
          >
            {counts[s]} {size === 'sm' ? s[0].toUpperCase() : s}
          </Badge>
        </Tooltip>
      ))}
    </Group>
  );
}

/** Quarantine banner shown at the top of the component page. */
export function QuarantineBanner({ scans }: { scans?: ComponentScans }) {
  if (!scans?.quarantined) return null;
  return (
    <Alert color="red" variant="light" icon={<IconLock size={20} />} title="Quarantined — downloads are blocked" mb="md">
      <Text size="sm">
        {scans.quarantineReason ||
          'This component has findings at or above the repository severity threshold. Clients receive an error instead of the artifact.'}
      </Text>
      <Text size="xs" c="dimmed" mt={4}>
        Publish a fixed version, or have an administrator waive the findings if they are not exploitable.
      </Text>
    </Alert>
  );
}

/** Threats found by file scanners (malware, policy blocks), not CVEs. */
const isThreat = (f: Finding) => !!f.kind && f.kind !== 'vulnerability';

function FindingsTable({
  result,
  severities,
  showWaived,
  canWaive,
  onWaive,
}: {
  result: ScanResult;
  severities: string[];
  showWaived: boolean;
  canWaive: boolean;
  onWaive: (f: Finding) => void;
}) {
  const rows = useMemo(
    () =>
      result.findings
        .filter((f) => severities.includes(f.severity) && (showWaived || !f.waived))
        .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9) || a.package.localeCompare(b.package)),
    [result.findings, severities, showWaived],
  );

  if (result.status === 'error') {
    return (
      <Alert color="gray" variant="light" icon={<IconAlertTriangle size={18} />} title="Scan failed" m="sm">
        <Text size="sm" ff="monospace" style={{ whiteSpace: 'pre-wrap' }}>
          {result.error || 'Unknown error'}
        </Text>
      </Alert>
    );
  }
  if (result.status === 'unsupported') {
    return (
      <Alert color="gray" variant="light" icon={<IconShieldOff size={18} />} m="sm">
        {result.scanner} cannot scan this kind of artifact.
      </Alert>
    );
  }
  if (result.findings.length === 0) {
    const files = result.files ?? [];
    if (files.length > 0) {
      const reused = files.filter((f) => f.cached).length;
      return (
        <Alert color="teal" variant="light" icon={<IconShieldCheck size={18} />} m="sm">
          No threats found in {files.length === 1 ? files[0].name : `${files.length} files`}
          {reused > 0 ? ` (${reused === files.length ? 'earlier analysis' : `${reused} earlier analyses`} reused)` : ''}.
        </Alert>
      );
    }
    return (
      <Alert color="teal" variant="light" icon={<IconShieldCheck size={18} />} m="sm">
        No vulnerabilities found{result.target ? ` in ${result.target}` : ''}.
      </Alert>
    );
  }
  if (rows.length === 0) {
    return (
      <Text size="sm" c="dimmed" p="md">
        No findings match the filter.
      </Text>
    );
  }
  const threats = rows.some(isThreat);
  const vulns = rows.some((f) => !isThreat(f));
  return (
    <ScrollArea.Autosize mah={560}>
      <Table stickyHeader verticalSpacing={8}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th w={110}>Severity</Table.Th>
            <Table.Th>{threats && !vulns ? 'Threat' : threats ? 'Finding' : 'Vulnerability'}</Table.Th>
            <Table.Th>{threats && !vulns ? 'File' : threats ? 'Package or file' : 'Package'}</Table.Th>
            <Table.Th>{threats && !vulns ? 'SHA-256' : 'Installed → fixed'}</Table.Th>
            {canWaive && <Table.Th w={60} />}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.map((f, i) => (
            <Table.Tr key={`${f.vulnId}-${f.package}-${i}`} style={f.waived ? { opacity: 0.6 } : undefined}>
              <Table.Td>
                <SeverityBadge severity={f.severity} />
              </Table.Td>
              <Table.Td>
                <Group gap={6} wrap="nowrap">
                  {f.url ? (
                    <Anchor href={f.url} target="_blank" rel="noreferrer" size="sm" ff="monospace" fw={500}>
                      <Group gap={3} wrap="nowrap" component="span">
                        {f.vulnId}
                        <IconExternalLink size={12} />
                      </Group>
                    </Anchor>
                  ) : (
                    <Text size="sm" ff="monospace" fw={500}>
                      {f.vulnId}
                    </Text>
                  )}
                  {isThreat(f) && (
                    <Badge size="xs" variant="light" color={f.kind === 'malware' ? 'red' : 'orange'} tt="none">
                      {f.kind === 'malware' ? 'malware' : 'blocked by policy'}
                    </Badge>
                  )}
                  {f.waived && (
                    <Badge size="xs" variant="outline" color="gray" leftSection={<IconShieldOff size={10} />} tt="none">
                      waived
                    </Badge>
                  )}
                </Group>
                {f.title && (
                  <Text size="xs" c="dimmed" lineClamp={2} maw={480}>
                    {f.title}
                  </Text>
                )}
              </Table.Td>
              <Table.Td>
                <Text size="sm" ff="monospace" style={{ wordBreak: 'break-all' }}>
                  {f.package}
                </Text>
              </Table.Td>
              <Table.Td>
                {isThreat(f) ? (
                  <Tooltip label="Start of the file's SHA-256 digest" withArrow>
                    <Text size="sm" ff="monospace" c="dimmed" style={{ whiteSpace: 'nowrap' }}>
                      {f.installedVersion ? `${f.installedVersion}…` : '?'}
                    </Text>
                  </Tooltip>
                ) : (
                  <Text size="sm" ff="monospace" style={{ whiteSpace: 'nowrap' }}>
                    {f.installedVersion || '?'}{' '}
                    <Text span c="dimmed">
                      →
                    </Text>{' '}
                    {f.fixedVersion ? (
                      <Text span c="teal" ff="monospace" size="sm">
                        {f.fixedVersion}
                      </Text>
                    ) : (
                      <Text span c="dimmed" size="xs">
                        no fix
                      </Text>
                    )}
                  </Text>
                )}
              </Table.Td>
              {canWaive && (
                <Table.Td>
                  {!f.waived && (
                    <Tooltip label={isThreat(f) ? 'Waive this exact threat' : 'Waive this finding'}>
                      <ActionIcon variant="subtle" color="gray" onClick={() => onWaive(f)} aria-label={`Waive ${f.vulnId}`}>
                        <IconShieldOff size={16} />
                      </ActionIcon>
                    </Tooltip>
                  )}
                </Table.Td>
              )}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </ScrollArea.Autosize>
  );
}

/** Scan summary, findings and jobs of a component. */
export function ScanPanel({ component, repository }: { component: Component; repository?: Repository }) {
  const id = component.id;
  const { admin } = useAuth();
  const qc = useQueryClient();
  const canScan = !!repository?.permissions.includes('write');
  const [pollUntil, setPollUntil] = useState(0);
  const scans = useComponentScans(id, (q) => {
    const d = q.state.data;
    const active = d?.jobs.some((j) => j.status === 'queued' || j.status === 'running') || d?.scanState === 'pending';
    return active || Date.now() < pollUntil ? 3000 : false;
  });
  const [severities, setSeverities] = useState<string[]>([...SEVERITIES]);
  const [showWaived, setShowWaived] = useState(true);
  const [waive, setWaive] = useState<Partial<WaiverInput> | null>(null);
  const [tab, setTab] = useState<string | null>(null);

  const scan = useMutation({
    mutationFn: () => unwrap(api.POST('/components/{id}/scan', { params: { path: { id } } })),
    onSuccess: (jobs) => {
      setPollUntil(Date.now() + 60_000);
      qc.invalidateQueries({ queryKey: qk2.componentScans(id) });
      notifySuccess(jobs.length ? `Queued ${jobs.length} scan job(s)` : 'No scanners configured for this repository', 'Scan requested');
    },
  });

  const header = (
    <Group justify="space-between" mb="sm" wrap="wrap">
      <Title order={5}>
        <Group gap={6} component="span">
          <IconRadar2 size={18} /> Vulnerability scan
        </Group>
      </Title>
      {canScan && !(scans.error instanceof ApiError && scans.error.notImplemented) && (
        <Button size="xs" variant="light" leftSection={<IconRadar2 size={14} />} loading={scan.isPending} onClick={() => scan.mutate()}>
          Scan now
        </Button>
      )}
    </Group>
  );

  if (scans.error) {
    return (
      <Paper p="lg">
        {header}
        <QueryError error={scans.error} retry={scans.refetch} feature="Vulnerability scanning" compact />
      </Paper>
    );
  }
  if (scans.isPending) {
    return (
      <Paper p="lg">
        {header}
        <Skeleton height={60} />
      </Paper>
    );
  }
  const d = scans.data;
  const counts = sumCounts(d.results);
  const activeTab = tab && d.results.some((r) => r.scanner === tab) ? tab : (d.results[0]?.scanner ?? null);
  const current = d.results.find((r) => r.scanner === activeTab);
  const totalFindings = d.results.reduce((n, r) => n + r.findings.length, 0);

  return (
    <Stack gap="md">
      <Paper p="lg">
        {header}
        <Group gap="xl" wrap="wrap" align="flex-start">
          <Stack gap={4}>
            <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
              State
            </Text>
            <ScanStateBadge state={d.scanState} quarantined={d.quarantined} size="lg" />
          </Stack>
          <Stack gap={4}>
            <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
              Last scanned
            </Text>
            <Text size="sm" title={formatDate(d.scannedAt)}>
              {d.scannedAt ? formatRelative(d.scannedAt) : 'never'}
            </Text>
          </Stack>
          <Stack gap={4}>
            <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
              Findings
            </Text>
            <SeverityCountsView counts={counts} />
          </Stack>
        </Group>
        {d.results.length === 0 && (
          <Text size="sm" c="dimmed" mt="md">
            {repository?.scan?.scanners?.length
              ? 'No scan results yet.'
              : 'Scanning is not configured for this repository.'}
            {canScan && repository?.scan?.scanners?.length ? ' Use "Scan now" to scan it.' : ''}
          </Text>
        )}
      </Paper>

      {d.results.length > 0 && (
        <Paper p={0}>
          <Group justify="space-between" p="sm" wrap="wrap" gap="xs">
            <Group gap="xs">
              <Text size="sm" fw={600} pl={4}>
                Findings
              </Text>
              <Text size="xs" c="dimmed">
                {totalFindings} total
              </Text>
            </Group>
            <Group gap="md" wrap="wrap">
              <Chip.Group multiple value={severities} onChange={setSeverities}>
                <Group gap={4}>
                  {SEVERITIES.map((s) => (
                    <Chip key={s} value={s} size="xs" color={severityColor(s)} variant="light">
                      {s}
                    </Chip>
                  ))}
                </Group>
              </Chip.Group>
              <Switch size="xs" label="Show waived" checked={showWaived} onChange={(e) => setShowWaived(e.currentTarget.checked)} />
            </Group>
          </Group>
          <Tabs value={activeTab} onChange={setTab}>
            <Tabs.List px="sm">
              {d.results.map((r) => (
                <Tabs.Tab
                  key={r.scanner}
                  value={r.scanner}
                  rightSection={
                    r.status === 'ok' ? (
                      <Badge size="xs" variant="light" color={r.findings.length ? 'orange' : 'teal'} circle={r.findings.length < 10}>
                        {r.findings.length}
                      </Badge>
                    ) : (
                      <Badge size="xs" variant="light" color="gray" tt="none">
                        {r.status}
                      </Badge>
                    )
                  }
                >
                  {r.scanner}
                </Tabs.Tab>
              ))}
            </Tabs.List>
          </Tabs>
          {current && (
            <>
              <Group gap="xs" px="md" py={8}>
                <Text size="xs" c="dimmed">
                  Scanned {formatRelative(current.scannedAt)}
                  {current.target ? ' · ' : ''}
                </Text>
                {current.target && (
                  <Text size="xs" c="dimmed" ff="monospace">
                    {current.target}
                  </Text>
                )}
              </Group>
              <FindingsTable
                result={current}
                severities={severities}
                showWaived={showWaived}
                canWaive={admin}
                onWaive={(f) =>
                  setWaive({
                    vulnId: f.vulnId,
                    repositoryPattern: component.repository,
                    componentPattern: component.version ? `${component.name}@${component.version}` : component.name,
                    reason: '',
                  })
                }
              />
            </>
          )}
        </Paper>
      )}

      {d.jobs.length > 0 && (
        <Paper p={0}>
          <Group justify="space-between" p="sm">
            <Text size="sm" fw={600} pl={4}>
              Recent scan jobs
            </Text>
            {admin && (
              <Anchor component={Link} to="/admin/scan-jobs" size="xs">
                Scan queue
              </Anchor>
            )}
          </Group>
          <Table verticalSpacing={6}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Scanner</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Reason</Table.Th>
                <Table.Th>Attempts</Table.Th>
                <Table.Th>Updated</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {d.jobs.map((j) => (
                <Table.Tr key={j.id}>
                  <Table.Td>
                    <Text size="sm">{j.scanner}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      <JobStatusBadge status={j.status} />
                      {j.error && (
                        <Tooltip label={j.error} multiline maw={420} withArrow>
                          <IconAlertTriangle size={14} color="var(--mantine-color-red-6)" />
                        </Tooltip>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {j.reason}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{j.attempts}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed" title={formatDate(j.updatedAt)}>
                      {formatRelative(j.finishedAt ?? j.updatedAt)}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Paper>
      )}
      {waive && <WaiverModal initial={waive} onClose={() => setWaive(null)} />}
    </Stack>
  );
}
