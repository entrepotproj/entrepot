import {
  ActionIcon,
  Anchor,
  Badge,
  Button,
  Group,
  Modal,
  Paper,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from '@mantine/core';
import { IconPlus, IconRobot, IconTrash } from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { api, unwrap, unwrapVoid, type User } from '../../api/client';
import { qk } from '../../api/queries';
import { CopyText } from '../../components/CodeBlock';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { TokenManager } from '../../components/TokenManager';
import { formatDate, formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;

/** Service account names are "sa:<name>"; the API path takes either form. */
const shortName = (u: User) => u.username.replace(/^sa:/, '');

function CreateModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const create = useMutation({
    mutationFn: () =>
      unwrap(api.POST('/service-accounts', { body: { name: name.trim(), description: description || undefined } })),
    onSuccess: (u) => {
      qc.invalidateQueries({ queryKey: qk.serviceAccounts });
      notifySuccess(`Service account ${u.username} created`);
      onClose();
      navigate(`/admin/service-accounts/${shortName(u)}`);
    },
  });
  const valid = NAME_RE.test(name);
  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>Create service account</Text>} centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) create.mutate();
        }}
      >
        <Stack>
          <TextInput
            label="Name"
            description={
              <>
                Bind roles to it as user <b>sa:{name || '<name>'}</b>.
              </>
            }
            value={name}
            onChange={(e) => setName(e.currentTarget.value.toLowerCase())}
            error={name && !valid ? "Lowercase letters, digits, '.', '_' and '-'" : null}
            required
            data-autofocus
          />
          <TextInput label="Description" value={description} onChange={(e) => setDescription(e.currentTarget.value)} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending} disabled={!valid}>
              Create
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function ServiceAccountDetail({ name }: { name: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [deleting, setDeleting] = useState(false);
  const { data: u, error, refetch } = useQuery({
    queryKey: [...qk.serviceAccounts, name],
    queryFn: () => unwrap(api.GET('/service-accounts/{name}', { params: { path: { name } } })),
  });
  const del = useMutation({
    mutationFn: () => unwrapVoid(api.DELETE('/service-accounts/{name}', { params: { path: { name } } })),
    onSuccess: () => {
      notifySuccess(`Service account ${name} deleted`);
      qc.invalidateQueries({ queryKey: qk.serviceAccounts });
      navigate('/admin/service-accounts');
    },
  });
  if (error) return <QueryError error={error} retry={refetch} />;
  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Service accounts', to: '/admin/service-accounts' }, { label: name }]}
        title={u?.username ?? `sa:${name}`}
        description={u?.displayName || 'Service account'}
        actions={
          <Button color="red" variant="light" leftSection={<IconTrash size={16} />} onClick={() => setDeleting(true)}>
            Delete
          </Button>
        }
      />
      <Paper p="md" mb="lg">
        <Group gap="xl">
          <div>
            <Text size="xs" c="dimmed">
              Role binding subject (user)
            </Text>
            <CopyText value={u?.username ?? `sa:${name}`} />
          </div>
          <div>
            <Text size="xs" c="dimmed">
              Created
            </Text>
            <Text size="sm">{formatDate(u?.createdAt)}</Text>
          </div>
          <div>
            <Text size="xs" c="dimmed">
              Grant access
            </Text>
            <Anchor component={Link} to="/admin/roles" size="sm">
              Create a role binding
            </Anchor>
          </div>
        </Group>
      </Paper>
      <Title order={4} mb="sm">
        Tokens
      </Title>
      <TokenManager
        queryKey={qk.serviceAccountTokens(name)}
        list={() => unwrap(api.GET('/service-accounts/{name}/tokens', { params: { path: { name } } }))}
        create={(body) => unwrap(api.POST('/service-accounts/{name}/tokens', { params: { path: { name } }, body }))}
        revoke={(id) =>
          unwrapVoid(api.DELETE('/service-accounts/{name}/tokens/{id}', { params: { path: { name, id } } }))
        }
        emptyHint="Create a token for the automation that uses this service account."
      />
      <ConfirmDelete
        opened={deleting}
        onClose={() => setDeleting(false)}
        onConfirm={() => del.mutate()}
        loading={del.isPending}
        title="Delete service account"
        confirmText={name}
      >
        Delete <b>sa:{name}</b> and revoke all of its tokens?
      </ConfirmDelete>
    </>
  );
}

export default function ServiceAccountsPage() {
  const { name } = useParams();
  if (name) return <ServiceAccountDetail key={name} name={name} />;
  return <ServiceAccountList />;
}

function ServiceAccountList() {
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const { data, isPending, error, refetch } = useQuery({
    queryKey: qk.serviceAccounts,
    queryFn: () => unwrap(api.GET('/service-accounts')),
  });
  const [deleting, setDeleting] = useState<User | null>(null);
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: (n: string) => unwrapVoid(api.DELETE('/service-accounts/{name}', { params: { path: { name: n } } })),
    onSuccess: () => {
      notifySuccess(`Service account ${deleting?.username} deleted`);
      setDeleting(null);
      qc.invalidateQueries({ queryKey: qk.serviceAccounts });
    },
  });
  return (
    <>
      <PageHeader
        title="Service accounts"
        description="Non-human identities for automation outside GitLab CI. Grant them roles and issue API tokens."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setCreating(true)}>
            Create service account
          </Button>
        }
      />
      <Paper p={0}>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={3} cols={4} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<IconRobot size={28} stroke={1.5} />}
            title="No service accounts"
            description="Create one for deployment scripts, Jenkins, Renovate and similar tools."
          />
        ) : (
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Description</Table.Th>
                <Table.Th>Created</Table.Th>
                <Table.Th>Last used</Table.Th>
                <Table.Th w={50} />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {data.map((u) => (
                <Table.Tr key={u.id} className="row-link" onClick={() => navigate(`/admin/service-accounts/${shortName(u)}`)}>
                  <Table.Td>
                    <Group gap={6}>
                      <IconRobot size={16} stroke={1.5} />
                      <Text size="sm" fw={600}>
                        {u.username}
                      </Text>
                      <Badge size="xs" variant="light" color="gray" radius="sm">
                        service
                      </Badge>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {u.displayName || '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {formatRelative(u.createdAt)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {u.lastLoginAt ? formatRelative(u.lastLoginAt) : 'Never'}
                    </Text>
                  </Table.Td>
                  <Table.Td onClick={(e) => e.stopPropagation()}>
                    <Tooltip label="Delete">
                      <ActionIcon variant="subtle" color="red" onClick={() => setDeleting(u)} aria-label="Delete">
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Tooltip>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Paper>
      {creating && <CreateModal onClose={() => setCreating(false)} />}
      <ConfirmDelete
        opened={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(shortName(deleting))}
        loading={del.isPending}
        title="Delete service account"
        confirmText={deleting ? shortName(deleting) : undefined}
      >
        Delete <b>{deleting?.username}</b> and revoke all of its tokens?
      </ConfirmDelete>
    </>
  );
}
