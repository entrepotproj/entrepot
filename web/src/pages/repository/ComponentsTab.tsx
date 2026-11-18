import { Anchor, Button, Group, Paper, Table, Text, TextInput } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconChevronLeft, IconChevronRight, IconPackage, IconSearch } from '@tabler/icons-react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { api, unwrap, type Repository } from '../../api/client';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatDate, formatRelative } from '../../lib/format';

const PAGE = 50;

export function ComponentsTab({ repository }: { repository: Repository }) {
  const name = repository.name;
  const [q, setQ] = useState('');
  const [debounced] = useDebouncedValue(q.trim(), 250);
  const [offset, setOffset] = useState(0);
  const navigate = useNavigate();

  const { data, isPending, isFetching, error, refetch } = useQuery({
    queryKey: ['components', name, debounced, offset],
    queryFn: () =>
      unwrap(
        api.GET('/repositories/{name}/components', {
          params: { path: { name }, query: { q: debounced || undefined, limit: PAGE, offset } },
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <Paper p={0}>
      <Group p="sm" justify="space-between">
        <TextInput
          size="xs"
          w={280}
          placeholder="Search by name"
          leftSection={<IconSearch size={14} />}
          value={q}
          onChange={(e) => {
            setQ(e.currentTarget.value);
            setOffset(0);
          }}
        />
        <Group gap="xs">
          <Text size="xs" c="dimmed">
            {data && data.length > 0 ? `${offset + 1}–${offset + data.length}` : ''}
          </Text>
          <Button
            size="xs"
            variant="default"
            leftSection={<IconChevronLeft size={14} />}
            disabled={offset === 0 || isFetching}
            onClick={() => setOffset(Math.max(0, offset - PAGE))}
          >
            Previous
          </Button>
          <Button
            size="xs"
            variant="default"
            rightSection={<IconChevronRight size={14} />}
            disabled={!data || data.length < PAGE || isFetching}
            onClick={() => setOffset(offset + PAGE)}
          >
            Next
          </Button>
        </Group>
      </Group>
      {error ? (
        <div style={{ padding: 12 }}>
          <QueryError error={error} retry={refetch} />
        </div>
      ) : isPending ? (
        <TableSkeleton rows={5} cols={3} />
      ) : data.length === 0 ? (
        <EmptyState
          icon={<IconPackage size={28} stroke={1.5} />}
          title={debounced ? 'No matching components' : 'No components'}
          description={
            debounced
              ? 'Try a different search.'
              : 'Components are packages with a name and version (for example an npm package version). Raw files are listed under Browse.'
          }
        />
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Version</Table.Th>
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
                  <Text size="sm" c="dimmed" title={formatDate(c.updatedAt)}>
                    {formatRelative(c.updatedAt)}
                  </Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </Paper>
  );
}
