import { Badge, Button, Code, Group, Paper, Popover, Select, Table, Text } from '@mantine/core';
import { IconChevronLeft, IconChevronRight, IconHistory, IconRefresh } from '@tabler/icons-react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useEffect, useMemo, useState } from 'react';
import { api, apiUrl, unwrap, type AuditEvent } from '../../api/client';
import {
  ClearFiltersButton,
  DateRangeFilter,
  DebouncedParamInput,
  ExportCsvButton,
  localToIso,
  useParamState,
} from '../../components/LogFilters';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatDate, formatRelative } from '../../lib/format';

const PAGE = 50;
const FILTER_KEYS = ['actor', 'action', 'target', 'from', 'to'];

/** Common action prefixes (the filter matches any action starting with the value). */
const ACTION_PREFIXES = [
  { value: 'login', label: 'login' },
  { value: 'repository.', label: 'repository.*' },
  { value: 'component.', label: 'component.*' },
  { value: 'asset.', label: 'asset.*' },
  { value: 'blobstore.', label: 'blobstore.*' },
  { value: 'token.', label: 'token.*' },
  { value: 'serviceaccount.', label: 'serviceaccount.*' },
  { value: 'role.', label: 'role.*' },
  { value: 'rolebinding.', label: 'rolebinding.*' },
  { value: 'gitlabpolicy.', label: 'gitlabpolicy.*' },
  { value: 'scanner.', label: 'scanner.*' },
  { value: 'waiver.', label: 'waiver.*' },
  { value: 'cleanup.', label: 'cleanup.* (runs)' },
  { value: 'cleanup_policy.', label: 'cleanup_policy.*' },
  { value: 'routing_rule.', label: 'routing_rule.*' },
  { value: 'signingkey.', label: 'signingkey.*' },
  { value: 'maintenance.', label: 'maintenance.*' },
];

function actionColor(a: string) {
  if (a.endsWith('.delete')) return 'red';
  if (a.endsWith('.create') || a.endsWith('.upload')) return 'teal';
  if (a.endsWith('.update')) return 'blue';
  if (a === 'login') return 'gray';
  return 'violet';
}

export default function AuditLogPage() {
  const [actor] = useParamState('actor');
  const [action, setAction] = useParamState('action');
  const [target] = useParamState('target');
  const [from] = useParamState('from');
  const [to] = useParamState('to');
  const filters = useMemo(
    () => ({
      actor: actor || undefined,
      action: action || undefined,
      target: target || undefined,
      from: localToIso(from),
      to: localToIso(to),
    }),
    [actor, action, target, from, to],
  );
  const filterKey = JSON.stringify(filters);
  const active = [actor, action, target, from, to].some(Boolean);

  // Stack of "before" cursors: [undefined] is the newest page.
  const [cursors, setCursors] = useState<(number | undefined)[]>([undefined]);
  useEffect(() => setCursors([undefined]), [filterKey]);
  const before = cursors[cursors.length - 1];
  const { data, isPending, isFetching, error, refetch } = useQuery({
    queryKey: ['audit', filters, before],
    queryFn: async () =>
      (await unwrap(api.GET('/audit-events', { params: { query: { ...filters, before, limit: PAGE } } }))) as AuditEvent[],
    placeholderData: keepPreviousData,
  });
  const actionOptions =
    action && !ACTION_PREFIXES.some((p) => p.value === action) ? [{ value: action, label: action }, ...ACTION_PREFIXES] : ACTION_PREFIXES;

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Security-relevant changes and sign-ins, newest first."
        actions={
          <>
            <Button
              variant="default"
              leftSection={<IconRefresh size={16} />}
              onClick={() => (cursors.length > 1 ? setCursors([undefined]) : refetch())}
              loading={isFetching && !isPending}
            >
              Refresh
            </Button>
            <ExportCsvButton href={apiUrl('/audit-events', { ...filters, format: 'csv' })} max={5000} />
          </>
        }
      />
      <Paper p={0}>
        <Group p="sm" gap="xs" align="flex-end" wrap="wrap" style={{ borderBottom: '1px solid var(--mantine-color-default-border)' }}>
          <DebouncedParamInput param="actor" label="Actor" placeholder="Name contains…" w={170} />
          <Select
            size="xs"
            label="Action"
            placeholder="All actions"
            data={actionOptions}
            value={action || null}
            onChange={(v) => setAction(v ?? '')}
            searchable
            clearable
            w={190}
            renderOption={({ option }) => (
              <Text size="xs" ff="monospace">
                {option.label}
              </Text>
            )}
          />
          <DebouncedParamInput param="target" label="Target" placeholder="Target contains…" w={170} mono />
          <DateRangeFilter />
          <ClearFiltersButton keys={FILTER_KEYS} active={active} />
        </Group>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={8} cols={5} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<IconHistory size={28} stroke={1.5} />}
            title="No audit events"
            description={active ? 'No events match these filters.' : undefined}
          />
        ) : (
          <Table.ScrollContainer minWidth={820}>
            <Table verticalSpacing="xs">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={190}>Time</Table.Th>
                  <Table.Th>Actor</Table.Th>
                  <Table.Th>Action</Table.Th>
                  <Table.Th>Target</Table.Th>
                  <Table.Th>Details</Table.Th>
                  <Table.Th>Remote IP</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.map((e) => {
                  const hasDetails = Object.keys(e.details ?? {}).length > 0;
                  return (
                    <Table.Tr key={e.id}>
                      <Table.Td>
                        <Text size="sm" title={formatRelative(e.at)}>
                          {formatDate(e.at)}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" fw={500}>
                          {e.actor}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Badge size="sm" variant="light" color={actionColor(e.action)} tt="none" radius="sm">
                          {e.action}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" ff="monospace" fz="xs" style={{ wordBreak: 'break-all' }}>
                          {e.target || '—'}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        {hasDetails ? (
                          <Popover width={420} position="bottom-start" shadow="md" withArrow>
                            <Popover.Target>
                              <Button size="compact-xs" variant="subtle">
                                View
                              </Button>
                            </Popover.Target>
                            <Popover.Dropdown>
                              <Code block fz="xs">
                                {JSON.stringify(e.details, null, 2)}
                              </Code>
                            </Popover.Dropdown>
                          </Popover>
                        ) : (
                          <Text size="sm" c="dimmed">
                            —
                          </Text>
                        )}
                      </Table.Td>
                      <Table.Td>
                        <Text size="xs" c="dimmed" ff="monospace">
                          {e.remoteIp || '—'}
                        </Text>
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      <Group justify="space-between" mt="sm">
        <Text size="xs" c="dimmed">
          Page {cursors.length}
        </Text>
        <Group gap="xs">
          <Button
            size="xs"
            variant="default"
            leftSection={<IconChevronLeft size={14} />}
            disabled={cursors.length === 1 || isFetching}
            onClick={() => setCursors((c) => c.slice(0, -1))}
          >
            Newer
          </Button>
          <Button
            size="xs"
            variant="default"
            rightSection={<IconChevronRight size={14} />}
            disabled={!data || data.length < PAGE || isFetching}
            onClick={() => data && setCursors((c) => [...c, data[data.length - 1].id])}
          >
            Older
          </Button>
        </Group>
      </Group>
    </>
  );
}
