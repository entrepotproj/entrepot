import {
  ActionIcon,
  Alert,
  Anchor,
  Autocomplete,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  Paper,
  Select,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from '@mantine/core';
import { IconBrandGitlab, IconInfoCircle, IconPencil, IconPlus, IconTrash, IconX } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router';
import { api, unwrap, unwrapVoid, type GitLabTrustPolicy, type GitLabTrustPolicyInput } from '../../api/client';
import { qk, useGitLabPolicies, useSystemInfo } from '../../api/queries';
import { CodeBlock } from '../../components/CodeBlock';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

const CLAIMS: { value: string; example: string }[] = [
  { value: 'project_path', example: 'platform/api or platform/**' },
  { value: 'namespace_path', example: 'platform' },
  { value: 'ref', example: 'main or release/*' },
  { value: 'ref_type', example: 'branch or tag' },
  { value: 'ref_protected', example: 'true' },
  { value: 'environment', example: 'production' },
  { value: 'pipeline_source', example: 'push, schedule, merge_request_event' },
];

type Cond = { key: string; value: string };

function IdTokenHelp({ aud }: { aud: string }) {
  return (
    <Alert variant="light" color="blue" icon={<IconInfoCircle size={18} />} title="How GitLab CI authentication works">
      <Stack gap={8}>
        <Text size="sm">
          GitLab issues each job a signed OIDC <Code>id_token</Code> when the job declares <Code>id_tokens:</Code>. Entrepot
          verifies the token against the trusted GitLab instance, then matches its claims against the conditions of each
          trust policy (all conditions must match; values are globs). A matching policy can then be granted roles with a{' '}
          <Anchor component={Link} to="/admin/roles" size="sm">
            role binding
          </Anchor>{' '}
          of subject type “GitLab trust policy”.
        </Text>
        <CodeBlock
          code={`publish:\n  id_tokens:\n    ENTREPOT_ID_TOKEN:\n      aud: ${aud}\n  script:\n    - npm config set //HOST/repository/REPO/:_authToken "$ENTREPOT_ID_TOKEN"\n    - npm publish`}
        />
      </Stack>
    </Alert>
  );
}

function PolicyModal({ policy, onClose }: { policy: GitLabTrustPolicy | null; onClose: () => void }) {
  const editing = !!policy;
  const qc = useQueryClient();
  const { data: info } = useSystemInfo();
  const instances = info?.gitlabInstances ?? [];
  const [name, setName] = useState(policy?.name ?? '');
  const [description, setDescription] = useState(policy?.description ?? '');
  const [gitlab, setGitlab] = useState<string | null>(policy?.gitlab ?? instances[0] ?? null);
  const [conds, setConds] = useState<Cond[]>(
    policy
      ? Object.entries(policy.conditions).map(([key, value]) => ({ key, value }))
      : [
          { key: 'project_path', value: '' },
          { key: 'ref_protected', value: 'true' },
        ],
  );

  const save = useMutation({
    mutationFn: (body: GitLabTrustPolicyInput) =>
      editing
        ? unwrap(api.PUT('/gitlab-trust-policies/{name}', { params: { path: { name: body.name } }, body }))
        : unwrap(api.POST('/gitlab-trust-policies', { body })),
    onSuccess: (p) => {
      qc.invalidateQueries({ queryKey: qk.gitlabPolicies });
      notifySuccess(`Trust policy ${p.name} saved`);
      onClose();
    },
  });

  const setCond = (i: number, patch: Partial<Cond>) =>
    setConds((cs) => cs.map((c, j) => (j === i ? { ...c, ...patch } : c)));
  const filled = conds.filter((c) => c.key.trim() && c.value.trim());
  const keys = filled.map((c) => c.key.trim());
  const dupes = keys.length !== new Set(keys).size;
  const partial = conds.some((c) => !!c.key.trim() !== !!c.value.trim());
  const valid = !!name.trim() && !!gitlab && filled.length > 0 && !dupes && !partial;

  return (
    <Modal
      opened
      onClose={onClose}
      title={<Text fw={600}>{editing ? `Edit trust policy ${policy.name}` : 'Create GitLab trust policy'}</Text>}
      size="xl"
      centered
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!valid) return;
          save.mutate({
            name: name.trim(),
            description,
            gitlab: gitlab!,
            conditions: Object.fromEntries(filled.map((c) => [c.key.trim(), c.value.trim()])),
          });
        }}
      >
        <Stack>
          <Group grow align="flex-start">
            <TextInput
              label="Name"
              value={name}
              onChange={(e) => setName(e.currentTarget.value.toLowerCase())}
              disabled={editing}
              required
              data-autofocus
            />
            <Select
              label="GitLab instance"
              data={instances}
              value={gitlab}
              onChange={setGitlab}
              required
              allowDeselect={false}
              error={instances.length === 0 ? 'No GitLab instances configured (auth.gitlab)' : null}
            />
          </Group>
          <Textarea
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.currentTarget.value)}
            autosize
          />
          <div>
            <Text size="sm" fw={500}>
              Conditions
            </Text>
            <Text size="xs" c="dimmed" mb={8}>
              id_token claim → glob pattern. All conditions must match. <Code>*</Code> matches within a path segment,{' '}
              <Code>**</Code> across segments.
            </Text>
            <Stack gap={6}>
              {conds.map((c, i) => (
                <Group key={i} gap={6} wrap="nowrap" align="flex-start">
                  <Autocomplete
                    placeholder="claim"
                    data={CLAIMS.map((x) => x.value).filter((k) => k === c.key || !conds.some((o) => o.key === k))}
                    value={c.key}
                    onChange={(v) => setCond(i, { key: v })}
                    w={220}
                    styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
                  />
                  <TextInput
                    placeholder={CLAIMS.find((x) => x.value === c.key)?.example ?? 'pattern'}
                    value={c.value}
                    onChange={(e) => setCond(i, { value: e.currentTarget.value })}
                    style={{ flex: 1 }}
                    styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
                  />
                  <ActionIcon
                    variant="subtle"
                    color="gray"
                    size="lg"
                    onClick={() => setConds((cs) => cs.filter((_, j) => j !== i))}
                    aria-label="Remove condition"
                  >
                    <IconX size={16} />
                  </ActionIcon>
                </Group>
              ))}
            </Stack>
            <Button
              variant="subtle"
              size="xs"
              mt={6}
              leftSection={<IconPlus size={14} />}
              onClick={() => setConds((cs) => [...cs, { key: '', value: '' }])}
            >
              Add condition
            </Button>
            {dupes && (
              <Text size="xs" c="red" mt={4}>
                Each claim can only appear once.
              </Text>
            )}
            {partial && (
              <Text size="xs" c="dimmed" mt={4}>
                Fill in both the claim and the pattern for each condition, or remove it.
              </Text>
            )}
          </div>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending} disabled={!valid}>
              {editing ? 'Save' : 'Create policy'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

export default function GitLabPoliciesPage() {
  const { data, isPending, error, refetch } = useGitLabPolicies();
  const { data: info } = useSystemInfo();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<GitLabTrustPolicy | 'new' | null>(null);
  const [deleting, setDeleting] = useState<GitLabTrustPolicy | null>(null);
  const del = useMutation({
    mutationFn: (name: string) => unwrapVoid(api.DELETE('/gitlab-trust-policies/{name}', { params: { path: { name } } })),
    onSuccess: () => {
      notifySuccess(`Trust policy ${deleting?.name} deleted`);
      setDeleting(null);
      qc.invalidateQueries({ queryKey: qk.gitlabPolicies });
      qc.invalidateQueries({ queryKey: qk.roleBindings });
    },
  });
  const noInstances = info && info.gitlabInstances.length === 0;
  const aud = (info?.baseUrl || window.location.origin).replace(/\/+$/, '');

  return (
    <>
      <PageHeader
        title="GitLab trust policies"
        description="Let GitLab CI/CD jobs authenticate with their id_token — no stored secrets."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')} disabled={noInstances}>
            Create policy
          </Button>
        }
      />
      <Stack gap="md">
        {noInstances && (
          <Alert color="orange" variant="light" icon={<IconInfoCircle size={18} />} title="No GitLab instances configured">
            Add a trusted GitLab instance under <Code>auth.gitlab</Code> in the server configuration to create trust
            policies.
          </Alert>
        )}
        <Paper p={0}>
          {error ? (
            <div style={{ padding: 12 }}>
              <QueryError error={error} retry={refetch} />
            </div>
          ) : isPending ? (
            <TableSkeleton rows={3} cols={4} />
          ) : data.length === 0 ? (
            <EmptyState
              icon={<IconBrandGitlab size={28} stroke={1.5} />}
              title="No trust policies"
              description="Create a policy that matches your projects, then bind it to a role."
            />
          ) : (
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>GitLab</Table.Th>
                  <Table.Th>Conditions</Table.Th>
                  <Table.Th>Updated</Table.Th>
                  <Table.Th w={80} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.map((p) => (
                  <Table.Tr key={p.name}>
                    <Table.Td>
                      <Text size="sm" fw={600}>
                        {p.name}
                      </Text>
                      {p.description && (
                        <Text size="xs" c="dimmed">
                          {p.description}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" color="orange" leftSection={<IconBrandGitlab size={12} />} tt="none" radius="sm">
                        {p.gitlab}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Stack gap={2}>
                        {Object.entries(p.conditions).map(([k, v]) => (
                          <Text key={k} size="xs" ff="monospace">
                            <Text span c="dimmed" ff="monospace" size="xs">
                              {k}
                            </Text>{' '}
                            = {v}
                          </Text>
                        ))}
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed">
                        {formatRelative(p.updatedAt)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={2} wrap="nowrap">
                        <Tooltip label="Edit">
                          <ActionIcon variant="subtle" color="gray" onClick={() => setEditing(p)} aria-label="Edit">
                            <IconPencil size={16} />
                          </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Delete">
                          <ActionIcon variant="subtle" color="red" onClick={() => setDeleting(p)} aria-label="Delete">
                            <IconTrash size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
        </Paper>
        <IdTokenHelp aud={aud} />
      </Stack>
      {editing && <PolicyModal policy={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      <ConfirmDelete
        opened={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(deleting.name)}
        loading={del.isPending}
        title="Delete trust policy"
        confirmText={deleting?.name}
      >
        Delete <b>{deleting?.name}</b>? Role bindings that reference it are deleted too.
      </ConfirmDelete>
    </>
  );
}
