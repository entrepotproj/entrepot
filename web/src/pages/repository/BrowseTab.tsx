import { Anchor, Breadcrumbs, Drawer, Group, Paper, Table, Text } from '@mantine/core';
import { IconFile, IconFolder, IconFolderOpen, IconHome } from '@tabler/icons-react';
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { api, unwrap, type Repository } from '../../api/client';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatBytes } from '../../lib/format';
import { AssetDetail } from './AssetDetail';

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;

export function BrowseTab({ repository }: { repository: Repository }) {
  const [params, setParams] = useSearchParams();
  const path = params.get('path') ?? '';
  const assetId = params.get('asset');
  const name = repository.name;

  const { data, isPending, error, refetch } = useQuery({
    queryKey: ['browse', name, path],
    queryFn: () => unwrap(api.GET('/repositories/{name}/browse', { params: { path: { name }, query: { path } } })),
  });

  const entries = useMemo(
    () =>
      [...(data ?? [])].sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1)),
    [data],
  );

  const update = (p: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(p)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setParams(next);
  };

  const segments = path.split('/').filter(Boolean);
  const crumbs = [
    <Anchor key="root" size="sm" onClick={() => update({ path: null })}>
      <Group gap={4} wrap="nowrap">
        <IconHome size={14} /> {name}
      </Group>
    </Anchor>,
    ...segments.map((seg, i) => {
      const p = segments.slice(0, i + 1).join('/') + '/';
      return i === segments.length - 1 ? (
        <Text key={p} size="sm" fw={500}>
          {seg}
        </Text>
      ) : (
        <Anchor key={p} size="sm" onClick={() => update({ path: p })}>
          {seg}
        </Anchor>
      );
    }),
  ];

  return (
    <>
      <Paper p={0}>
        <Group px="md" py="sm" style={{ borderBottom: '1px solid var(--mantine-color-default-border)' }}>
          <Breadcrumbs separatorMargin={6}>{crumbs}</Breadcrumbs>
        </Group>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={5} cols={2} />
        ) : entries.length === 0 ? (
          <EmptyState
            icon={<IconFolderOpen size={28} stroke={1.5} />}
            title={path ? 'This folder is empty' : 'This repository is empty'}
            description={
              repository.kind === 'proxy'
                ? 'Artifacts appear here once clients request them through the proxy.'
                : repository.kind === 'group'
                  ? 'Groups do not store content; browse the member repositories instead.'
                  : ['raw', 'pypi', 'npm'].includes(repository.format)
                    ? 'Publish packages with your client or use the Upload tab.'
                    : 'Publish with your client; see “Set up client” above.'
            }
          />
        ) : (
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th w={140} ta="right">
                  Size
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {path && (
                <Table.Tr
                  className="row-link"
                  onClick={() => update({ path: segments.slice(0, -1).join('/') ? segments.slice(0, -1).join('/') + '/' : null })}
                >
                  <Table.Td colSpan={2}>
                    <Group gap="sm">
                      <IconFolder size={18} color="var(--mantine-color-yellow-6)" />
                      <Text size="sm">..</Text>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              )}
              {entries.map((e) => (
                <Table.Tr
                  key={e.path}
                  className="row-link"
                  onClick={() =>
                    e.isDir
                      ? update({ path: e.path.endsWith('/') ? e.path : e.path + '/' })
                      : e.assetId && update({ asset: e.assetId })
                  }
                >
                  <Table.Td>
                    <Group gap="sm" wrap="nowrap">
                      {e.isDir ? (
                        <IconFolder size={18} color="var(--mantine-color-yellow-6)" fill="var(--mantine-color-yellow-light)" />
                      ) : (
                        <IconFile size={18} color="var(--mantine-color-dimmed)" />
                      )}
                      <Text size="sm" fw={e.isDir ? 500 : 400} style={{ wordBreak: 'break-all' }}>
                        {e.name}
                      </Text>
                    </Group>
                  </Table.Td>
                  <Table.Td ta="right">
                    <Text size="sm" c="dimmed">
                      {e.isDir ? '—' : formatBytes(e.size)}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Paper>
      {entries.length > 0 && (
        <Text size="xs" c="dimmed" mt="xs">
          {plural(entries.filter((e) => e.isDir).length, 'folder')}, {plural(entries.filter((e) => !e.isDir).length, 'file')}
        </Text>
      )}
      <Drawer
        opened={!!assetId}
        onClose={() => update({ asset: null })}
        position="right"
        size="lg"
        title={<Text fw={600}>Asset details</Text>}
      >
        {assetId && <AssetDetail id={assetId} showOpenLink onDeleted={() => update({ asset: null })} />}
      </Drawer>
    </>
  );
}
