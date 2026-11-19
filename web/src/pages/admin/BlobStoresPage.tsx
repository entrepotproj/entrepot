import {
  ActionIcon,
  Badge,
  Button,
  Group,
  Modal,
  Paper,
  PasswordInput,
  SegmentedControl,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core';
import { IconCloud, IconDatabase, IconPencil, IconPlus, IconServer, IconTrash } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, unwrap, unwrapVoid, type BlobStore, type BlobStoreInput } from '../../api/client';
import { qk, useBlobStores } from '../../api/queries';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatBytes, formatNumber, formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;

function BlobStoreModal({ store, onClose }: { store: BlobStore | null; onClose: () => void }) {
  const editing = !!store;
  const qc = useQueryClient();
  const [name, setName] = useState(store?.name ?? '');
  const [type, setType] = useState<'file' | 's3'>(store?.type ?? 'file');
  const [path, setPath] = useState(store?.file?.path ?? '');
  const [s3, setS3] = useState({
    bucket: store?.s3?.bucket ?? '',
    region: store?.s3?.region ?? '',
    prefix: store?.s3?.prefix ?? '',
    endpoint: store?.s3?.endpoint ?? '',
    forcePathStyle: store?.s3?.forcePathStyle ?? false,
    accessKeyId: store?.s3?.accessKeyId ?? '',
    secretAccessKey: '',
    redirectDownloads: store?.s3?.redirectDownloads ?? false,
  });
  const setS = <K extends keyof typeof s3>(k: K, v: (typeof s3)[K]) => setS3((p) => ({ ...p, [k]: v }));

  const save = useMutation({
    mutationFn: (body: BlobStoreInput) =>
      editing
        ? unwrap(api.PUT('/blob-stores/{name}', { params: { path: { name: body.name } }, body }))
        : unwrap(api.POST('/blob-stores', { body })),
    onSuccess: (b) => {
      qc.invalidateQueries({ queryKey: qk.blobStores });
      notifySuccess(`Blob store ${b.name} ${editing ? 'updated' : 'created'}`);
      onClose();
    },
  });

  const opt = (v: string) => (v.trim() ? v.trim() : undefined);
  const submit = () => {
    const body: BlobStoreInput = { name: name.trim(), type };
    if (type === 'file') body.file = { path: path.trim() };
    else
      body.s3 = {
        bucket: s3.bucket.trim(),
        region: opt(s3.region),
        prefix: opt(s3.prefix),
        endpoint: opt(s3.endpoint),
        forcePathStyle: s3.forcePathStyle,
        accessKeyId: opt(s3.accessKeyId),
        secretAccessKey: opt(s3.secretAccessKey),
        redirectDownloads: s3.redirectDownloads,
      };
    save.mutate(body);
  };

  const valid = NAME_RE.test(name) && (type === 'file' ? path.trim() !== '' : s3.bucket.trim() !== '');

  return (
    <Modal
      opened
      onClose={onClose}
      title={<Text fw={600}>{editing ? `Edit blob store ${store.name}` : 'Create blob store'}</Text>}
      size="lg"
      centered
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) submit();
        }}
      >
        <Stack>
          <TextInput
            label="Name"
            value={name}
            onChange={(e) => setName(e.currentTarget.value.toLowerCase())}
            disabled={editing}
            required
            error={name && !NAME_RE.test(name) ? "Lowercase letters, digits, '.', '_' and '-'" : null}
            data-autofocus
          />
          <div>
            <Text size="sm" fw={500} mb={4}>
              Type
            </Text>
            <SegmentedControl
              value={type}
              onChange={(v) => setType(v as 'file' | 's3')}
              disabled={editing}
              data={[
                { value: 'file', label: 'File system' },
                { value: 's3', label: 'Amazon S3 / compatible' },
              ]}
            />
          </div>
          {type === 'file' ? (
            <TextInput
              label="Path"
              description="Directory on a mounted volume (PVC, EBS, EFS). Must be under one of the server's storage.allowedRoots."
              placeholder="/data/default"
              value={path}
              onChange={(e) => setPath(e.currentTarget.value)}
              required
            />
          ) : (
            <>
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <TextInput label="Bucket" value={s3.bucket} onChange={(e) => setS('bucket', e.currentTarget.value)} required />
                <TextInput
                  label="Region"
                  placeholder="eu-west-1"
                  value={s3.region}
                  onChange={(e) => setS('region', e.currentTarget.value)}
                />
                <TextInput
                  label="Prefix"
                  description="Optional key prefix inside the bucket"
                  placeholder="entrepot/"
                  value={s3.prefix}
                  onChange={(e) => setS('prefix', e.currentTarget.value)}
                />
                <TextInput
                  label="Endpoint"
                  description="Custom endpoint for MinIO / Ceph"
                  placeholder="https://minio.example.com"
                  value={s3.endpoint}
                  onChange={(e) => setS('endpoint', e.currentTarget.value)}
                />
                <TextInput
                  label="Access key ID"
                  description="Leave empty to use the AWS default chain (IRSA)"
                  value={s3.accessKeyId}
                  onChange={(e) => setS('accessKeyId', e.currentTarget.value)}
                  autoComplete="off"
                />
                <PasswordInput
                  label="Secret access key"
                  description={editing ? 'Leave empty to keep the stored secret' : 'Required with an access key ID'}
                  value={s3.secretAccessKey}
                  onChange={(e) => setS('secretAccessKey', e.currentTarget.value)}
                  autoComplete="new-password"
                />
              </SimpleGrid>
              <Switch
                label="Force path-style addressing"
                description="Needed by most S3-compatible servers (MinIO)"
                checked={s3.forcePathStyle}
                onChange={(e) => setS('forcePathStyle', e.currentTarget.checked)}
              />
              <Switch
                label="Redirect downloads"
                description="Redirect large downloads to presigned S3 URLs instead of streaming through Entrepot"
                checked={s3.redirectDownloads}
                onChange={(e) => setS('redirectDownloads', e.currentTarget.checked)}
              />
            </>
          )}
          <Text size="xs" c="dimmed">
            The server verifies the store is reachable and writable before saving.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending} disabled={!valid}>
              {editing ? 'Save' : 'Create'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

export default function BlobStoresPage() {
  const { data, isPending, error, refetch } = useBlobStores();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<BlobStore | 'new' | null>(null);
  const [deleting, setDeleting] = useState<BlobStore | null>(null);

  const del = useMutation({
    mutationFn: (name: string) => unwrapVoid(api.DELETE('/blob-stores/{name}', { params: { path: { name } } })),
    onSuccess: () => {
      notifySuccess(`Blob store ${deleting?.name} deleted`);
      setDeleting(null);
      qc.invalidateQueries({ queryKey: qk.blobStores });
    },
  });

  return (
    <>
      <PageHeader
        title="Blob stores"
        description="Where repositories keep artifact content: a mounted file system or an S3 bucket."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')}>
            Create blob store
          </Button>
        }
      />
      <Paper p={0}>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={3} cols={6} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<IconDatabase size={28} stroke={1.5} />}
            title="No blob stores"
            description="Create a blob store before creating repositories."
            action={
              <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')}>
                Create blob store
              </Button>
            }
          />
        ) : (
          <Table.ScrollContainer minWidth={820}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Type</Table.Th>
                  <Table.Th>Location</Table.Th>
                  <Table.Th ta="right">Blobs</Table.Th>
                  <Table.Th ta="right">Size</Table.Th>
                  <Table.Th ta="right">Repositories</Table.Th>
                  <Table.Th>Updated</Table.Th>
                  <Table.Th w={80} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.map((b) => (
                  <Table.Tr key={b.name}>
                    <Table.Td>
                      <Text size="sm" fw={600}>
                        {b.name}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge
                        variant="light"
                        color={b.type === 's3' ? 'orange' : 'gray'}
                        leftSection={b.type === 's3' ? <IconCloud size={12} /> : <IconServer size={12} />}
                        radius="sm"
                      >
                        {b.type}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace" fz="xs">
                        {b.type === 'file'
                          ? b.file?.path
                          : `s3://${b.s3?.bucket}/${b.s3?.prefix ?? ''}${b.s3?.endpoint ? ` @ ${b.s3.endpoint}` : ''}`}
                      </Text>
                    </Table.Td>
                    <Table.Td ta="right">{formatNumber(b.usage.blobCount)}</Table.Td>
                    <Table.Td ta="right">{formatBytes(b.usage.totalBytes)}</Table.Td>
                    <Table.Td ta="right">{formatNumber(b.usage.repositories)}</Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed">
                        {formatRelative(b.updatedAt)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={2} wrap="nowrap">
                        <Tooltip label="Edit">
                          <ActionIcon variant="subtle" color="gray" onClick={() => setEditing(b)} aria-label="Edit">
                            <IconPencil size={16} />
                          </ActionIcon>
                        </Tooltip>
                        <Tooltip label={b.usage.repositories > 0 ? 'In use by repositories' : 'Delete'}>
                          <ActionIcon
                            variant="subtle"
                            color="red"
                            onClick={() => setDeleting(b)}
                            disabled={b.usage.repositories > 0}
                            aria-label="Delete"
                          >
                            <IconTrash size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      {editing && <BlobStoreModal store={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      <ConfirmDelete
        opened={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(deleting.name)}
        loading={del.isPending}
        title="Delete blob store"
        confirmText={deleting?.name}
      >
        Delete the blob store <b>{deleting?.name}</b>? Only stores that no repository uses can be deleted.
      </ConfirmDelete>
    </>
  );
}
