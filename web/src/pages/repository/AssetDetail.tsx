import { Anchor, Badge, Button, Group, Skeleton, Stack, Text, Title } from '@mantine/core';
import { IconDownload, IconExternalLink, IconPackage, IconTrash } from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router';
import { api, unwrap, unwrapVoid, type Asset } from '../../api/client';
import { qk, useRepository } from '../../api/queries';
import { CopyText } from '../../components/CodeBlock';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { DetailList } from '../../components/DetailList';
import { JsonView } from '../../components/JsonView';
import { QueryError } from '../../components/states';
import { formatBytes, formatDate, formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

export function useAsset(id: string | null) {
  return useQuery({
    queryKey: ['assets', id],
    queryFn: () => unwrap(api.GET('/assets/{id}', { params: { path: { id: id! } } })),
    enabled: !!id,
  });
}

function When({ at }: { at?: string }) {
  if (!at) return <Text size="sm" c="dimmed">—</Text>;
  return (
    <Text size="sm" title={formatDate(at)}>
      {formatDate(at)}{' '}
      <Text span size="xs" c="dimmed">
        ({formatRelative(at)})
      </Text>
    </Text>
  );
}

/** Asset metadata, download and delete. Used in the browse drawer and on /assets/:id. */
export function AssetDetail({
  id,
  onDeleted,
  showOpenLink,
}: {
  id: string;
  onDeleted?: (a: Asset) => void;
  showOpenLink?: boolean;
}) {
  const { data: a, isPending, error, refetch } = useAsset(id);
  const repo = useRepository(a?.repository ?? '');
  const canDelete = !!repo.data?.permissions.includes('delete');
  const [confirm, setConfirm] = useState(false);
  const qc = useQueryClient();

  const del = useMutation({
    mutationFn: () => unwrapVoid(api.DELETE('/assets/{id}', { params: { path: { id } } })),
    onSuccess: () => {
      setConfirm(false);
      if (a) onDeleted?.(a);
      notifySuccess(`Deleted ${a?.path}`);
      qc.invalidateQueries({ queryKey: ['browse', a?.repository] });
      qc.invalidateQueries({ queryKey: ['components'] });
      qc.invalidateQueries({ queryKey: qk.repository(a?.repository ?? '') });
      qc.removeQueries({ queryKey: ['assets', id], exact: true });
    },
  });

  if (error) return <QueryError error={error} retry={refetch} />;
  if (isPending || !a) {
    return (
      <Stack>
        <Skeleton height={24} width="60%" />
        <Skeleton height={200} />
      </Stack>
    );
  }

  return (
    <Stack gap="lg">
      <div>
        <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
          Asset
        </Text>
        <Title order={4} style={{ wordBreak: 'break-all' }} ff="monospace" fw={600}>
          {a.path}
        </Title>
      </div>
      <Group gap="xs">
        {a.downloadUrl && (
          <Button component="a" href={a.downloadUrl} leftSection={<IconDownload size={16} />} size="sm">
            Download
          </Button>
        )}
        {showOpenLink && (
          <Button
            component={Link}
            to={`/assets/${a.id}`}
            variant="default"
            size="sm"
            leftSection={<IconExternalLink size={16} />}
          >
            Open page
          </Button>
        )}
        {canDelete && (
          <Button color="red" variant="light" size="sm" leftSection={<IconTrash size={16} />} onClick={() => setConfirm(true)}>
            Delete
          </Button>
        )}
      </Group>
      <DetailList
        items={[
          [
            'Repository',
            <Anchor component={Link} to={`/repositories/${a.repository}`} size="sm">
              {a.repository}
            </Anchor>,
          ],
          [
            'Size',
            <Text size="sm">
              {formatBytes(a.size)}{' '}
              <Text span size="xs" c="dimmed">
                ({a.size.toLocaleString()} bytes)
              </Text>
            </Text>,
          ],
          ['Digest', <CopyText value={a.digest} />],
          ['Content type', <Badge variant="default" tt="none" radius="sm" fw={500}>{a.contentType || 'unknown'}</Badge>],
          ['Created by', a.createdBy || '—'],
          ['Created', <When at={a.createdAt} />],
          ['Updated', <When at={a.updatedAt} />],
          ['Cached', <When at={a.cachedAt} />],
          ['Last downloaded', <When at={a.lastDownloadedAt} />],
          ...(a.componentId
            ? ([
                [
                  'Component',
                  <Anchor component={Link} to={`/components/${a.componentId}`} size="sm">
                    <Group gap={4} wrap="nowrap">
                      <IconPackage size={14} /> View component
                    </Group>
                  </Anchor>,
                ],
              ] as [string, React.ReactNode][])
            : []),
        ]}
      />
      <div>
        <Text size="sm" fw={600} mb={6}>
          Attributes
        </Text>
        <JsonView value={a.attrs} />
      </div>
      <ConfirmDelete
        opened={confirm}
        onClose={() => setConfirm(false)}
        onConfirm={() => del.mutate()}
        loading={del.isPending}
        title="Delete asset"
      >
        Permanently delete <b>{a.path}</b> from {a.repository}? This cannot be undone.
      </ConfirmDelete>
    </Stack>
  );
}
