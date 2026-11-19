import { Anchor, Button, Grid, Group, Paper, Skeleton, Stack, Table, Text, Title } from '@mantine/core';
import { IconDownload, IconPackage, IconTrash } from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { api, unwrap, unwrapVoid } from '../api/client';
import { qk, useComponentScans, useRepository } from '../api/queries';
import { FormatBadge, ScanStateBadge } from '../components/badges';
import { ConfirmDelete } from '../components/ConfirmDelete';
import { DetailList } from '../components/DetailList';
import { JsonView } from '../components/JsonView';
import { PageHeader } from '../components/PageHeader';
import { QueryError } from '../components/states';
import { formatBytes, formatDate } from '../lib/format';
import { notifySuccess } from '../lib/notify';
import { QuarantineBanner, ScanPanel } from './repository/ScanPanel';

export function ComponentPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState(false);
  const { data, isPending, error, refetch } = useQuery({
    queryKey: ['component', id],
    queryFn: () => unwrap(api.GET('/components/{id}', { params: { path: { id } } })),
  });
  const c = data?.component;
  const repo = useRepository(c?.repository ?? '');
  const canDelete = !!repo.data?.permissions.includes('delete');
  const scans = useComponentScans(c?.id ?? '');

  const del = useMutation({
    mutationFn: () => unwrapVoid(api.DELETE('/components/{id}', { params: { path: { id } } })),
    onSuccess: () => {
      setConfirm(false);
      notifySuccess(`Deleted ${c?.name}@${c?.version}`);
      qc.invalidateQueries({ queryKey: ['components'] });
      qc.invalidateQueries({ queryKey: ['browse', c?.repository] });
      qc.invalidateQueries({ queryKey: qk.repository(c?.repository ?? '') });
      navigate(`/repositories/${c?.repository}/components`);
    },
  });

  if (error) return <QueryError error={error} retry={refetch} />;
  if (isPending || !data || !c) {
    return (
      <Stack>
        <Skeleton height={40} width={300} />
        <Skeleton height={240} />
      </Stack>
    );
  }

  const total = data.assets.reduce((n, a) => n + a.size, 0);

  return (
    <>
      <PageHeader
        crumbs={[
          { label: 'Repositories', to: '/repositories' },
          { label: c.repository, to: `/repositories/${c.repository}/components` },
          { label: `${c.name}${c.version ? '@' + c.version : ''}` },
        ]}
        title={
          <Group gap="sm">
            <IconPackage size={26} stroke={1.5} />
            <span>{c.name}</span>
            {c.version && (
              <Text span c="dimmed" ff="monospace" fz="xl">
                {c.version}
              </Text>
            )}
          </Group>
        }
        actions={
          <>
            <FormatBadge format={c.format} size="lg" />
            {(scans.data || c.scanState) && (
              <ScanStateBadge
                state={scans.data?.scanState ?? c.scanState}
                quarantined={scans.data?.quarantined ?? c.quarantined}
                size="lg"
              />
            )}
            {canDelete && (
              <Button color="red" variant="light" leftSection={<IconTrash size={16} />} onClick={() => setConfirm(true)}>
                Delete
              </Button>
            )}
          </>
        }
      />
      <QuarantineBanner scans={scans.data ?? (c.quarantined ? { scanState: c.scanState ?? 'vulnerable', quarantined: true, results: [], jobs: [] } : undefined)} />
      <Grid>
        <Grid.Col span={{ base: 12, md: 5 }}>
          <Paper p="lg">
            <Title order={5} mb="sm">
              Details
            </Title>
            <DetailList
              items={[
                ['Name', c.name],
                ['Version', c.version || '—'],
                [
                  'Repository',
                  <Anchor component={Link} to={`/repositories/${c.repository}`} size="sm">
                    {c.repository}
                  </Anchor>,
                ],
                ['Assets', `${data.assets.length} (${formatBytes(total)})`],
                ['Created', formatDate(c.createdAt)],
                ['Updated', formatDate(c.updatedAt)],
              ]}
            />
            <Text size="sm" fw={600} mt="md" mb={6}>
              Attributes
            </Text>
            <JsonView value={c.attrs} />
          </Paper>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 7 }}>
          <Paper p={0}>
            <Title order={5} p="md" pb="xs">
              Assets
            </Title>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Path</Table.Th>
                  <Table.Th ta="right">Size</Table.Th>
                  <Table.Th w={50} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.assets.map((a) => (
                  <Table.Tr key={a.id}>
                    <Table.Td>
                      <Anchor component={Link} to={`/assets/${a.id}`} size="sm" ff="monospace" style={{ wordBreak: 'break-all' }}>
                        {a.path}
                      </Anchor>
                    </Table.Td>
                    <Table.Td ta="right">
                      <Text size="sm" c="dimmed" style={{ whiteSpace: 'nowrap' }}>
                        {formatBytes(a.size)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {a.downloadUrl && (
                        <Button component="a" href={a.downloadUrl} size="compact-xs" variant="subtle" aria-label="Download">
                          <IconDownload size={14} />
                        </Button>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
                {data.assets.length === 0 && (
                  <Table.Tr>
                    <Table.Td colSpan={3}>
                      <Text size="sm" c="dimmed">
                        No assets
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                )}
              </Table.Tbody>
            </Table>
          </Paper>
        </Grid.Col>
      </Grid>
      <div style={{ marginTop: 'var(--mantine-spacing-md)' }}>
        <ScanPanel component={c} repository={repo.data} />
      </div>
      <ConfirmDelete
        opened={confirm}
        onClose={() => setConfirm(false)}
        onConfirm={() => del.mutate()}
        loading={del.isPending}
        title="Delete component"
      >
        Delete{' '}
        <b>
          {c.name}
          {c.version ? '@' + c.version : ''}
        </b>{' '}
        and its {data.assets.length} asset(s)? This cannot be undone.
      </ConfirmDelete>
    </>
  );
}
