import {
  ActionIcon,
  Alert,
  Autocomplete,
  Badge,
  Button,
  Checkbox,
  Code,
  Group,
  List,
  Modal,
  Paper,
  Select,
  Stack,
  Table,
  Tabs,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from '@mantine/core';
import { IconInfoCircle, IconLink, IconLock, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import {
  api,
  unwrap,
  unwrapVoid,
  type Action,
  type Role,
  type RoleBinding,
  type RoleBindingInput,
  type RoleInput,
  type SubjectType,
} from '../../api/client';
import { qk, useGitLabPolicies, useRoles } from '../../api/queries';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatDate, formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

const ACTIONS: { value: Action; help: string }[] = [
  { value: 'read', help: 'Browse, search and download' },
  { value: 'write', help: 'Publish, push and upload' },
  { value: 'delete', help: 'Delete assets and components' },
  { value: 'admin', help: 'Configure repositories; on pattern * grants system administration' },
];

const actionColor: Record<string, string> = { read: 'blue', write: 'teal', delete: 'orange', admin: 'grape' };

function ActionBadges({ actions }: { actions: string[] }) {
  return (
    <Group gap={4}>
      {actions.map((a) => (
        <Badge key={a} size="sm" variant="light" color={actionColor[a] ?? 'gray'} radius="sm">
          {a}
        </Badge>
      ))}
    </Group>
  );
}

function RoleModal({ role, onClose }: { role: Role | null; onClose: () => void }) {
  const editing = !!role;
  const qc = useQueryClient();
  const [name, setName] = useState(role?.name ?? '');
  const [description, setDescription] = useState(role?.description ?? '');
  const [actions, setActions] = useState<Action[]>(role?.actions ?? ['read']);
  const save = useMutation({
    mutationFn: (body: RoleInput) =>
      editing
        ? unwrap(api.PUT('/roles/{name}', { params: { path: { name: body.name } }, body }))
        : unwrap(api.POST('/roles', { body })),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: qk.roles });
      notifySuccess(`Role ${r.name} saved`);
      onClose();
    },
  });
  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>{editing ? `Edit role ${role.name}` : 'Create role'}</Text>} centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ name: name.trim(), description, actions });
        }}
      >
        <Stack>
          <TextInput
            label="Name"
            value={name}
            onChange={(e) => setName(e.currentTarget.value.toLowerCase())}
            disabled={editing}
            required
            data-autofocus
          />
          <Textarea label="Description" value={description} onChange={(e) => setDescription(e.currentTarget.value)} autosize />
          <Checkbox.Group label="Actions" value={actions} onChange={(v) => setActions(v as Action[])} required>
            <Stack gap={6} mt={8}>
              {ACTIONS.map((a) => (
                <Checkbox
                  key={a.value}
                  value={a.value}
                  label={
                    <Text size="sm">
                      <b>{a.value}</b>{' '}
                      <Text span c="dimmed" size="sm">
                        — {a.help}
                      </Text>
                    </Text>
                  }
                />
              ))}
            </Stack>
          </Checkbox.Group>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending} disabled={!name.trim() || actions.length === 0}>
              {editing ? 'Save' : 'Create'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function RolesTab() {
  const { data, isPending, error, refetch } = useRoles();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Role | 'new' | null>(null);
  const [deleting, setDeleting] = useState<Role | null>(null);
  const del = useMutation({
    mutationFn: (name: string) => unwrapVoid(api.DELETE('/roles/{name}', { params: { path: { name } } })),
    onSuccess: () => {
      notifySuccess(`Role ${deleting?.name} deleted`);
      setDeleting(null);
      qc.invalidateQueries({ queryKey: qk.roles });
      qc.invalidateQueries({ queryKey: qk.roleBindings });
    },
  });
  return (
    <>
      <Paper p={0}>
        <Group justify="space-between" p="sm">
          <Text size="sm" c="dimmed" px={4}>
            Roles are named sets of actions. Built-in roles cannot be changed.
          </Text>
          <Button size="xs" leftSection={<IconPlus size={14} />} onClick={() => setEditing('new')}>
            Create role
          </Button>
        </Group>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={4} cols={4} />
        ) : (
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Description</Table.Th>
                <Table.Th>Actions</Table.Th>
                <Table.Th w={80} />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {data.map((r) => (
                <Table.Tr key={r.name}>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      <Text size="sm" fw={600}>
                        {r.name}
                      </Text>
                      {r.builtin && (
                        <Badge size="xs" variant="outline" color="gray" leftSection={<IconLock size={10} />} radius="sm">
                          built-in
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {r.description || '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <ActionBadges actions={r.actions} />
                  </Table.Td>
                  <Table.Td>
                    {!r.builtin && (
                      <Group gap={2} wrap="nowrap">
                        <Tooltip label="Edit">
                          <ActionIcon variant="subtle" color="gray" onClick={() => setEditing(r)} aria-label="Edit">
                            <IconPencil size={16} />
                          </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Delete">
                          <ActionIcon variant="subtle" color="red" onClick={() => setDeleting(r)} aria-label="Delete">
                            <IconTrash size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Group>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Paper>
      {editing && <RoleModal role={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      <ConfirmDelete
        opened={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(deleting.name)}
        loading={del.isPending}
        title="Delete role"
      >
        Delete the role <b>{deleting?.name}</b>? Bindings that use it stop granting access.
      </ConfirmDelete>
    </>
  );
}

const SUBJECT_TYPES: { value: SubjectType; label: string; color: string }[] = [
  { value: 'user', label: 'User', color: 'blue' },
  { value: 'group', label: 'OIDC group', color: 'cyan' },
  { value: 'gitlab_policy', label: 'GitLab trust policy', color: 'orange' },
  { value: 'authenticated', label: 'All authenticated', color: 'gray' },
];

function SubjectBadge({ type }: { type: string }) {
  const t = SUBJECT_TYPES.find((s) => s.value === type);
  return (
    <Badge variant="light" color={t?.color ?? 'gray'} radius="sm" tt="none">
      {t?.label ?? type}
    </Badge>
  );
}

function BindingModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const roles = useRoles();
  const policies = useGitLabPolicies();
  const users = useQuery({ queryKey: qk.users, queryFn: () => unwrap(api.GET('/users')) });
  const [role, setRole] = useState<string | null>(null);
  const [subjectType, setSubjectType] = useState<SubjectType>('group');
  const [subject, setSubject] = useState('');
  const [pattern, setPattern] = useState('*');
  const create = useMutation({
    mutationFn: (body: RoleBindingInput) => unwrap(api.POST('/role-bindings', { body })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.roleBindings });
      notifySuccess('Role binding created');
      onClose();
    },
  });
  const needsSubject = subjectType !== 'authenticated';
  const valid = !!role && (!needsSubject || subject.trim() !== '');

  const groups = [...new Set((users.data ?? []).flatMap((u) => u.groups))].sort();
  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>Create role binding</Text>} centered size="lg">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!valid) return;
          create.mutate({
            role: role!,
            subjectType,
            subject: needsSubject ? subject.trim() : undefined,
            repositoryPattern: pattern.trim() || '*',
          });
        }}
      >
        <Stack>
          <Select
            label="Role"
            data={(roles.data ?? []).map((r) => ({ value: r.name, label: `${r.name} (${r.actions.join(', ')})` }))}
            value={role}
            onChange={setRole}
            required
            searchable
            data-autofocus
          />
          <Select
            label="Subject type"
            data={SUBJECT_TYPES.map((s) => ({ value: s.value, label: s.label }))}
            value={subjectType}
            onChange={(v) => {
              setSubjectType((v as SubjectType) ?? 'group');
              setSubject('');
            }}
            allowDeselect={false}
          />
          {subjectType === 'user' && (
            <Autocomplete
              label="Username"
              description="OIDC username, or sa:<name> for a service account"
              data={(users.data ?? []).map((u) => u.username)}
              value={subject}
              onChange={setSubject}
              required
            />
          )}
          {subjectType === 'group' && (
            <Autocomplete
              label="Group"
              description="Group name from the identity provider's groups claim"
              data={groups}
              value={subject}
              onChange={setSubject}
              required
            />
          )}
          {subjectType === 'gitlab_policy' && (
            <Select
              label="GitLab trust policy"
              data={(policies.data ?? []).map((p) => p.name)}
              value={subject || null}
              onChange={(v) => setSubject(v ?? '')}
              nothingFoundMessage="No trust policies — create one under GitLab trust"
              required
            />
          )}
          <TextInput
            label="Repository pattern"
            value={pattern}
            onChange={(e) => setPattern(e.currentTarget.value)}
            styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
          />
          <Alert variant="light" color="blue" icon={<IconInfoCircle size={18} />} p="sm">
            <Text size="xs">A glob over repository names:</Text>
            <List size="xs" spacing={2} mt={4}>
              <List.Item>
                <Code>*</Code> matches every repository. A role with <b>admin</b> on <Code>*</Code> makes the subject a
                system administrator.
              </List.Item>
              <List.Item>
                <Code>npm-*</Code> matches <Code>npm-internal</Code>, <Code>npm-public</Code>, …
              </List.Item>
              <List.Item>
                <Code>npm-*|pypi-*</Code> alternatives: matches if any alternative matches.
              </List.Item>
              <List.Item>
                <Code>team-a-releases</Code> matches exactly one repository.
              </List.Item>
            </List>
          </Alert>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending} disabled={!valid}>
              Create binding
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function BindingsTab() {
  const qc = useQueryClient();
  const { data, isPending, error, refetch } = useQuery({
    queryKey: qk.roleBindings,
    queryFn: () => unwrap(api.GET('/role-bindings')),
  });
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<RoleBinding | null>(null);
  const navigate = useNavigate();
  const del = useMutation({
    mutationFn: (id: string) => unwrapVoid(api.DELETE('/role-bindings/{id}', { params: { path: { id } } })),
    onSuccess: () => {
      notifySuccess('Role binding deleted');
      setDeleting(null);
      qc.invalidateQueries({ queryKey: qk.roleBindings });
    },
  });
  return (
    <>
      <Paper p={0}>
        <Group justify="space-between" p="sm">
          <Text size="sm" c="dimmed" px={4}>
            Bindings grant a role to a subject on repositories matching a pattern.
          </Text>
          <Button size="xs" leftSection={<IconPlus size={14} />} onClick={() => setCreating(true)}>
            Create binding
          </Button>
        </Group>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={4} cols={5} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<IconLink size={28} stroke={1.5} />}
            title="No role bindings"
            description="Without bindings only administrators and anonymous-readable repositories are accessible."
          />
        ) : (
          <Table.ScrollContainer minWidth={720}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Role</Table.Th>
                  <Table.Th>Subject type</Table.Th>
                  <Table.Th>Subject</Table.Th>
                  <Table.Th>Repositories</Table.Th>
                  <Table.Th>Created</Table.Th>
                  <Table.Th w={50} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.map((b) => (
                  <Table.Tr key={b.id}>
                    <Table.Td>
                      <Text size="sm" fw={600}>
                        {b.role}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <SubjectBadge type={b.subjectType} />
                    </Table.Td>
                    <Table.Td>
                      {b.subjectType === 'gitlab_policy' ? (
                        <Text
                          size="sm"
                          c="blue"
                          style={{ cursor: 'pointer' }}
                          onClick={() => navigate('/admin/gitlab')}
                        >
                          {b.subject}
                        </Text>
                      ) : (
                        <Text size="sm">{b.subject || <Text span c="dimmed" size="sm">any signed-in principal</Text>}</Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Code>{b.repositoryPattern}</Code>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed" title={formatDate(b.createdAt)}>
                        {formatRelative(b.createdAt)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Tooltip label="Delete">
                        <ActionIcon variant="subtle" color="red" onClick={() => setDeleting(b)} aria-label="Delete">
                          <IconTrash size={16} />
                        </ActionIcon>
                      </Tooltip>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      {creating && <BindingModal onClose={() => setCreating(false)} />}
      <ConfirmDelete
        opened={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(deleting.id)}
        loading={del.isPending}
        title="Delete role binding"
      >
        Remove <b>{deleting?.role}</b> from{' '}
        <b>{deleting?.subject || 'all authenticated principals'}</b> on <Code>{deleting?.repositoryPattern}</Code>?
      </ConfirmDelete>
    </>
  );
}

export default function RolesPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') === 'roles' ? 'roles' : 'bindings';
  return (
    <>
      <PageHeader
        title="Roles & bindings"
        description="Role-based access control for repositories."
      />
      <Tabs value={tab} onChange={(v) => setParams(v === 'roles' ? { tab: 'roles' } : {}, { replace: true })}>
        <Tabs.List mb="md">
          <Tabs.Tab value="bindings">Role bindings</Tabs.Tab>
          <Tabs.Tab value="roles">Roles</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="bindings">
          <BindingsTab />
        </Tabs.Panel>
        <Tabs.Panel value="roles">
          <RolesTab />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
