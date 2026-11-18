import { Anchor, Badge, Button, Group, Stack, Table, Text, Tooltip } from '@mantine/core';
import { IconActivity, IconDownload, IconTrash, IconUpload, type Icon } from '@tabler/icons-react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { Link } from 'react-router';
import { api, unwrap, type ActivityEvent, type ActivityQuery } from '../api/client';
import { formatBytes, formatDate, formatRelative } from '../lib/format';
import { FormatIcon } from './badges';
import { EmptyState, QueryError, TableSkeleton } from './states';

export const ACTIVITY_PAGE = 50;

const kinds: Record<string, { color: string; icon: Icon }> = {
  download: { color: 'blue', icon: IconDownload },
  upload: { color: 'teal', icon: IconUpload },
  delete: { color: 'red', icon: IconTrash },
};

export function ActivityKindBadge({ kind }: { kind: string }) {
  const k = kinds[kind] ?? { color: 'gray', icon: IconActivity };
  return (
    <Badge size="sm" variant="light" color={k.color} radius="sm" tt="none" leftSection={<k.icon size={12} />}>
      {kind}
    </Badge>
  );
}

const actorKindColor: Record<string, string> = {
  user: 'blue',
  'service-account': 'grape',
  service_account: 'grape',
  gitlab: 'orange',
  anonymous: 'gray',
  bootstrap: 'red',
};

/** Paged activity query (newest first, "Load more" via the `before` cursor). */
export function useActivity(filters: Omit<ActivityQuery, 'before' | 'limit' | 'format'>, enabled = true) {
  return useInfiniteQuery({
    queryKey: ['activity', filters],
    queryFn: async ({ pageParam }) =>
      (await unwrap(
        api.GET('/activity', { params: { query: { ...filters, before: pageParam, limit: ACTIVITY_PAGE } } }),
      )) as ActivityEvent[],
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.length < ACTIVITY_PAGE ? undefined : last[last.length - 1].id),
    enabled,
  });
}

/** Shortens a user agent to its first product token(s), e.g. "npm/10.8.2 node/v22.11.0". */
function shortAgent(ua: string): string {
  if (!ua) return '—';
  const first = ua.split(' ').slice(0, 2).join(' ');
  return first.length > 38 ? first.slice(0, 36) + '…' : first;
}

export function ActivityTable({
  query,
  showRepository = true,
  emptyHint,
}: {
  query: ReturnType<typeof useActivity>;
  showRepository?: boolean;
  emptyHint?: string;
}) {
  const { data, error, isPending, refetch, fetchNextPage, hasNextPage, isFetchingNextPage } = query;
  if (error) {
    return (
      <Stack p="sm">
        <QueryError error={error} retry={refetch} feature="Activity log" />
      </Stack>
    );
  }
  if (isPending) return <TableSkeleton rows={8} cols={showRepository ? 7 : 6} />;
  const rows = data.pages.flat();
  if (rows.length === 0) {
    return (
      <EmptyState
        icon={<IconActivity size={28} stroke={1.5} />}
        title="No activity"
        description={emptyHint ?? 'No downloads, uploads or deletes match these filters.'}
      />
    );
  }
  return (
    <>
      <Table.ScrollContainer minWidth={showRepository ? 1080 : 960}>
        <Table verticalSpacing="xs" fz="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th w={170}>Time</Table.Th>
              <Table.Th w={110}>Kind</Table.Th>
              {showRepository && <Table.Th>Repository</Table.Th>}
              <Table.Th>Component / path</Table.Th>
              <Table.Th>Actor</Table.Th>
              <Table.Th>Client</Table.Th>
              <Table.Th ta="right">Bytes</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((e) => (
              <Table.Tr key={e.id}>
                <Table.Td>
                  <Tooltip label={formatRelative(e.at)} withArrow openDelay={300}>
                    <Text size="sm" style={{ whiteSpace: 'nowrap' }}>
                      {formatDate(e.at)}
                    </Text>
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  <ActivityKindBadge kind={e.kind} />
                </Table.Td>
                {showRepository && (
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      <FormatIcon format={e.format} size={16} />
                      <Anchor component={Link} to={`/repositories/${e.repository}`} size="sm" fw={500}>
                        {e.repository}
                      </Anchor>
                    </Group>
                  </Table.Td>
                )}
                <Table.Td maw={340}>
                  {e.component && e.componentId ? (
                    <Anchor component={Link} to={`/components/${e.componentId}`} size="sm" fw={500}>
                      {e.component}
                    </Anchor>
                  ) : e.component ? (
                    <Text size="sm" fw={500}>
                      {e.component}
                    </Text>
                  ) : null}
                  <Text ff="monospace" fz="xs" c="dimmed" truncate="start" ta="left" title={e.path}>
                    {e.path || '—'}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Group gap={6} wrap="nowrap">
                    <Text size="sm" fw={500} truncate="end" maw={180} title={e.actor}>
                      {e.actor || 'anonymous'}
                    </Text>
                    {e.actorKind && (
                      <Badge size="xs" variant="outline" color={actorKindColor[e.actorKind] ?? 'gray'} radius="sm" tt="none">
                        {e.actorKind}
                      </Badge>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" ff="monospace" c="dimmed">
                    {e.remoteIp || '—'}
                  </Text>
                  <Tooltip label={e.userAgent || 'No user agent'} withArrow multiline maw={420} openDelay={200}>
                    <Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }}>
                      {shortAgent(e.userAgent)}
                    </Text>
                  </Tooltip>
                </Table.Td>
                <Table.Td ta="right" style={{ whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}>
                  {e.bytes > 0 ? formatBytes(e.bytes) : '—'}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      <Group justify="space-between" p="sm" style={{ borderTop: '1px solid var(--mantine-color-default-border)' }}>
        <Text size="xs" c="dimmed">
          {rows.length} event{rows.length === 1 ? '' : 's'} shown
        </Text>
        {hasNextPage ? (
          <Button size="xs" variant="default" onClick={() => fetchNextPage()} loading={isFetchingNextPage}>
            Load more
          </Button>
        ) : (
          <Text size="xs" c="dimmed">
            End of log
          </Text>
        )}
      </Group>
    </>
  );
}
