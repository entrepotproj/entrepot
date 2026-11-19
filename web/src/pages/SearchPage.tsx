import { Anchor, Button, Group, Paper, Select, Table, Text, TextInput } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconChevronLeft, IconChevronRight, IconSearch } from '@tabler/icons-react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { api, unwrap } from '../api/client';
import { useRepositories, useSystemInfo } from '../api/queries';
import { FormatBadge, formatLabel } from '../components/badges';
import { PageHeader } from '../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../components/states';
import { formatRelative } from '../lib/format';

const PAGE = 50;

export function SearchPage() {
  const [params, setParams] = useSearchParams();
  const q = params.get('q') ?? '';
  const format = params.get('format') ?? '';
  const repository = params.get('repository') ?? '';
  const offset = Number(params.get('offset') ?? 0) || 0;
  const [debounced] = useDebouncedValue(q.trim(), 250);
  const { data: info } = useSystemInfo();
  const { data: repos } = useRepositories();
  const navigate = useNavigate();

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== 'offset') next.delete('offset');
    setParams(next, { replace: true });
  };

  const { data, isPending, isFetching, error, refetch } = useQuery({
    queryKey: ['search', debounced, format, repository, offset],
    queryFn: () =>
      unwrap(
        api.GET('/search', {
          params: {
            query: {
              q: debounced || undefined,
              format: format || undefined,
              repository: repository || undefined,
              limit: PAGE,
              offset,
            },
          },
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader title="Search" description="Find components (packages and versions) across all repositories you can read." />
      <Paper p={0}>
        <Group p="sm" gap="sm" wrap="wrap">
          <TextInput
            placeholder="Package name"
            leftSection={<IconSearch size={16} />}
            value={q}
            onChange={(e) => set('q', e.currentTarget.value)}
            style={{ flex: 1, minWidth: 220 }}
            autoFocus
          />
          <Select
            placeholder="All formats"
            data={(info?.formats ?? []).map((f) => ({ value: f.name, label: formatLabel(f.name) }))}
            value={format || null}
            onChange={(v) => set('format', v ?? '')}
            clearable
            w={160}
          />
          <Select
            placeholder="All repositories"
            data={(repos ?? [])
              .filter((r) => !format || r.format === format)
              .map((r) => r.name)
              .sort()}
            value={repository || null}
            onChange={(v) => set('repository', v ?? '')}
            clearable
            searchable
            w={220}
          />
        </Group>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={6} cols={4} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<IconSearch size={28} stroke={1.5} />}
            title="No components found"
            description={debounced ? `Nothing matches “${debounced}”.` : 'No components in the repositories you can read.'}
          />
        ) : (
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Version</Table.Th>
                <Table.Th>Format</Table.Th>
                <Table.Th>Repository</Table.Th>
                <Table.Th>Updated</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {data.map((c) => (
                <Table.Tr key={c.id} className="row-link" onClick={() => navigate(`/components/${c.id}`)}>
                  <Table.Td>
                    <Anchor component={Link} to={`/components/${c.id}`} size="sm" fw={500} onClick={(e) => e.stopPropagation()}>
                      {c.name}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {c.version || '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <FormatBadge format={c.format} size="sm" />
                  </Table.Td>
                  <Table.Td>
                    <Anchor
                      component={Link}
                      to={`/repositories/${c.repository}`}
                      size="sm"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {c.repository}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {formatRelative(c.updatedAt)}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Paper>
      <Group justify="flex-end" mt="sm" gap="xs">
        <Button
          size="xs"
          variant="default"
          leftSection={<IconChevronLeft size={14} />}
          disabled={offset === 0 || isFetching}
          onClick={() => set('offset', String(Math.max(0, offset - PAGE)))}
        >
          Previous
        </Button>
        <Button
          size="xs"
          variant="default"
          rightSection={<IconChevronRight size={14} />}
          disabled={!data || data.length < PAGE || isFetching}
          onClick={() => set('offset', String(offset + PAGE))}
        >
          Next
        </Button>
      </Group>
    </>
  );
}
