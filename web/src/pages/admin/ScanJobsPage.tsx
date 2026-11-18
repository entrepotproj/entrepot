import { Anchor, Group, Loader, Paper, SegmentedControl, Switch, Table, Text, Tooltip } from '@mantine/core';
import { IconAlertTriangle, IconListCheck } from '@tabler/icons-react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { api, isNotImplemented, unwrap, type ScanJob } from '../../api/client';
import { qk2 } from '../../api/queries';
import { JobStatusBadge } from '../../components/badges';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatDate, formatRelative } from '../../lib/format';

type Status = NonNullable<ScanJob['status']>;

function duration(j: ScanJob): string {
  if (!j.finishedAt) return '';
  const ms = new Date(j.finishedAt).getTime() - new Date(j.createdAt).getTime();
  if (!(ms >= 0)) return '';
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.round(ms / 60_000)} min`;
}

export default function ScanJobsPage() {
  const [params, setParams] = useSearchParams();
  const status = (params.get('status') ?? '') as Status | '';
  const [auto, setAuto] = useState(true);

  const { data, isPending, isFetching, error, refetch } = useQuery({
    queryKey: qk2.scanJobs(status || undefined),
    queryFn: () => unwrap(api.GET('/scan-jobs', { params: { query: { status: status || undefined, limit: 200 } } })),
    refetchInterval: (q) => (auto && !(q.state.error && isNotImplemented(q.state.error)) ? 5000 : false),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader title="Scan jobs" description="The vulnerability scan queue: queued, running and recent jobs." />
      <Paper p={0}>
        <Group p="sm" justify="space-between" wrap="wrap">
          <SegmentedControl
            size="xs"
            value={status || 'all'}
            onChange={(v) => {
              const next = new URLSearchParams(params);
              if (v === 'all') next.delete('status');
              else next.set('status', v);
              setParams(next, { replace: true });
            }}
            data={[
              { value: 'all', label: 'All' },
              { value: 'queued', label: 'Queued' },
              { value: 'running', label: 'Running' },
              { value: 'done', label: 'Done' },
              { value: 'failed', label: 'Failed' },
            ]}
          />
          <Group gap="sm">
            {isFetching && !isPending && <Loader size={14} />}
            <Switch size="xs" label="Auto-refresh (5 s)" checked={auto} onChange={(e) => setAuto(e.currentTarget.checked)} />
          </Group>
        </Group>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} feature="Vulnerability scanning" />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={6} cols={7} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<IconListCheck size={28} stroke={1.5} />}
            title={status ? `No ${status} jobs` : 'The queue is empty'}
            description="Jobs are created when components are uploaded or cached by a proxy, on rescans, and with “Scan now”."
          />
        ) : (
          <Table.ScrollContainer minWidth={900}>
            <Table verticalSpacing={8}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Component</Table.Th>
                  <Table.Th>Repository</Table.Th>
                  <Table.Th>Scanner</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Reason</Table.Th>
                  <Table.Th ta="right">Attempts</Table.Th>
                  <Table.Th>Created</Table.Th>
                  <Table.Th>Finished</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.map((j) => (
                  <Table.Tr key={j.id}>
                    <Table.Td>
                      <Anchor component={Link} to={`/components/${j.componentId}`} size="sm" ff="monospace">
                        {j.component}
                      </Anchor>
                    </Table.Td>
                    <Table.Td>
                      <Anchor component={Link} to={`/repositories/${j.repository}`} size="sm">
                        {j.repository}
                      </Anchor>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{j.scanner}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={6} wrap="nowrap">
                        <JobStatusBadge status={j.status} />
                        {j.error && (
                          <Tooltip label={j.error} multiline maw={480} withArrow>
                            <IconAlertTriangle size={15} color="var(--mantine-color-red-6)" />
                          </Tooltip>
                        )}
                      </Group>
                      {j.status === 'queued' && j.runAfter && new Date(j.runAfter).getTime() > Date.now() && (
                        <Text size="xs" c="dimmed">
                          retry {formatRelative(j.runAfter)}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed">
                        {j.reason}
                      </Text>
                    </Table.Td>
                    <Table.Td ta="right">
                      <Text size="sm">{j.attempts}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed" title={formatDate(j.createdAt)}>
                        {formatRelative(j.createdAt)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed" title={formatDate(j.finishedAt)}>
                        {j.finishedAt ? `${formatRelative(j.finishedAt)}` : '—'}
                        {duration(j) && (
                          <Text span size="xs" c="dimmed">
                            {' '}
                            ({duration(j)})
                          </Text>
                        )}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
    </>
  );
}
