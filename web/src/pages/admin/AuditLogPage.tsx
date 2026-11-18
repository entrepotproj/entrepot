import { Badge, Button, Code, Group, Paper, Popover, Table, Text } from '@mantine/core';
import { IconChevronLeft, IconChevronRight, IconHistory, IconRefresh } from '@tabler/icons-react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { api, unwrap } from '../../api/client';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatDate, formatRelative } from '../../lib/format';

const PAGE = 50;

function actionColor(a: string) {
  if (a.endsWith('.delete')) return 'red';
  if (a.endsWith('.create') || a.endsWith('.upload')) return 'teal';
  if (a.endsWith('.update')) return 'blue';
  if (a === 'login') return 'gray';
  return 'violet';
}

export default function AuditLogPage() {
  // Stack of "before" cursors: [undefined] is the newest page.
  const [cursors, setCursors] = useState<(number | undefined)[]>([undefined]);
  const before = cursors[cursors.length - 1];
  const { data, isPending, isFetching, error, refetch } = useQuery({
    queryKey: ['audit', before],
    queryFn: () => unwrap(api.GET('/audit-events', { params: { query: { before, limit: PAGE } } })),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Security-relevant changes and sign-ins, newest first."
        actions={
          <Button
            variant="default"
            leftSection={<IconRefresh size={16} />}
            onClick={() => (cursors.length > 1 ? setCursors([undefined]) : refetch())}
            loading={isFetching && !isPending}
          >
            Refresh
          </Button>
        }
      />
      <Paper p={0}>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={8} cols={5} />
        ) : data.length === 0 ? (
          <EmptyState icon={<IconHistory size={28} stroke={1.5} />} title="No audit events" />
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
