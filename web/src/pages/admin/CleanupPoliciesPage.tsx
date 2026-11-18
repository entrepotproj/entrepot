import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Code,
  Divider,
  Group,
  Modal,
  NumberInput,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from '@mantine/core';
import { IconAlertTriangle, IconEraser, IconEye, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router';
import {
  api,
  isNotImplemented,
  unwrap,
  unwrapVoid,
  type CleanupCriteria,
  type CleanupPolicy,
  type CleanupPolicyInput,
  type CleanupRunResult,
} from '../../api/client';
import { qk, qk2, useCleanupPolicies, useRepositories, useSystemInfo } from '../../api/queries';
import { FormatBadge, formatLabel } from '../../components/badges';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';
import { CleanupResultView } from '../repository/RepositoryExtras';

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;

/** Human-readable criteria, one phrase per criterion. */
export function describeCriteria(c: CleanupCriteria): string[] {
  const out: string[] = [];
  if (c.publishedOlderThanDays) out.push(`published more than ${c.publishedOlderThanDays} days ago`);
  if (c.lastDownloadedOlderThanDays) out.push(`not downloaded for ${c.lastDownloadedOlderThanDays} days`);
  if (c.nameRegex) out.push(`name matches /${c.nameRegex}/`);
  if (c.versionRegex) out.push(`version matches /${c.versionRegex}/`);
  if (c.prereleaseOnly) out.push('pre-release versions only');
  if (c.untaggedOlderThanDays) out.push(`untagged manifests older than ${c.untaggedOlderThanDays} days`);
  if (c.keepLatest) out.push(`always keep the newest ${c.keepLatest}`);
  return out;
}

function regexError(s: string): string | null {
  if (!s) return null;
  try {
    new RegExp(s);
    return null;
  } catch (e) {
    return e instanceof Error ? e.message.replace(/^Invalid regular expression: /, '') : 'Invalid regular expression';
  }
}

type Form = {
  name: string;
  description: string;
  format: string;
  publishedOlderThanDays: number | '';
  lastDownloadedOlderThanDays: number | '';
  nameRegex: string;
  versionRegex: string;
  prereleaseOnly: boolean;
  keepLatest: number | '';
  untaggedOlderThanDays: number | '';
};

function PolicyModal({ policy, onClose }: { policy: CleanupPolicy | null; onClose: () => void }) {
  const editing = !!policy;
  const qc = useQueryClient();
  const { data: info } = useSystemInfo();
  const c = policy?.criteria ?? {};
  const [f, setF] = useState<Form>({
    name: policy?.name ?? '',
    description: policy?.description ?? '',
    format: policy?.format ?? '',
    publishedOlderThanDays: c.publishedOlderThanDays ?? (editing ? '' : 90),
    lastDownloadedOlderThanDays: c.lastDownloadedOlderThanDays ?? '',
    nameRegex: c.nameRegex ?? '',
    versionRegex: c.versionRegex ?? '',
    prereleaseOnly: c.prereleaseOnly ?? false,
    keepLatest: c.keepLatest ?? (editing ? '' : 5),
    untaggedOlderThanDays: c.untaggedOlderThanDays ?? '',
  });
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF((p) => ({ ...p, [k]: v }));
  const num = (v: number | '') => (v === '' || v === 0 ? undefined : v);

  const criteria: CleanupCriteria = {
    publishedOlderThanDays: num(f.publishedOlderThanDays),
    lastDownloadedOlderThanDays: num(f.lastDownloadedOlderThanDays),
    nameRegex: f.nameRegex.trim() || undefined,
    versionRegex: f.versionRegex.trim() || undefined,
    prereleaseOnly: f.prereleaseOnly || undefined,
    keepLatest: f.keepLatest === '' ? undefined : f.keepLatest,
    untaggedOlderThanDays: f.format === 'docker' || !f.format ? num(f.untaggedOlderThanDays) : undefined,
  };
  const selecting = describeCriteria({ ...criteria, keepLatest: undefined });
  const errors = {
    name: !NAME_RE.test(f.name) ? "Lowercase letters, digits, '.', '_' and '-'" : null,
    nameRegex: regexError(f.nameRegex.trim()),
    versionRegex: regexError(f.versionRegex.trim()),
    criteria: selecting.length === 0 ? 'Set at least one criterion that selects components' : null,
  };
  const valid = Object.values(errors).every((e) => !e);

  const save = useMutation({
    mutationFn: (body: CleanupPolicyInput) =>
      editing
        ? unwrap(api.PUT('/cleanup-policies/{name}', { params: { path: { name: body.name } }, body }))
        : unwrap(api.POST('/cleanup-policies', { body })),
    onSuccess: (p) => {
      qc.invalidateQueries({ queryKey: qk2.cleanupPolicies });
      notifySuccess(`Cleanup policy ${p.name} saved`);
      onClose();
    },
  });

  const formats = (info?.formats ?? []).map((x) => ({ value: x.name, label: formatLabel(x.name) }));

  return (
    <Modal
      opened
      onClose={onClose}
      title={<Text fw={600}>{editing ? `Edit cleanup policy ${policy.name}` : 'Create cleanup policy'}</Text>}
      size="xl"
      centered
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) save.mutate({ name: f.name.trim(), description: f.description, format: f.format, criteria });
        }}
      >
        <Stack>
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <TextInput
              label="Name"
              placeholder="old-snapshots"
              value={f.name}
              onChange={(e) => set('name', e.currentTarget.value.toLowerCase())}
              disabled={editing}
              error={f.name ? errors.name : null}
              required
              data-autofocus
            />
            <Select
              label="Format"
              description="Restrict the policy to repositories of one format"
              data={[{ value: '', label: 'Any format' }, ...formats]}
              value={f.format}
              onChange={(v) => set('format', v ?? '')}
              allowDeselect={false}
            />
          </SimpleGrid>
          <Textarea
            label="Description"
            autosize
            minRows={1}
            value={f.description}
            onChange={(e) => set('description', e.currentTarget.value)}
          />
          <Divider label="Criteria — all set criteria must match" labelPosition="left" />
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <NumberInput
              label="Published more than (days) ago"
              placeholder="e.g. 90"
              min={1}
              value={f.publishedOlderThanDays}
              onChange={(v) => set('publishedOlderThanDays', typeof v === 'number' ? v : '')}
            />
            <NumberInput
              label="Not downloaded for (days)"
              description="Never-downloaded components count from their publish date"
              placeholder="e.g. 180"
              min={1}
              value={f.lastDownloadedOlderThanDays}
              onChange={(v) => set('lastDownloadedOlderThanDays', typeof v === 'number' ? v : '')}
            />
            <TextInput
              label="Name regex"
              description={
                <>
                  e.g. <Code fz={11}>^@acme/experimental-</Code>
                </>
              }
              value={f.nameRegex}
              onChange={(e) => set('nameRegex', e.currentTarget.value)}
              error={errors.nameRegex}
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
            <TextInput
              label="Version regex"
              description={
                <>
                  e.g. <Code fz={11}>-SNAPSHOT$</Code> or <Code fz={11}>^0\.</Code>
                </>
              }
              value={f.versionRegex}
              onChange={(e) => set('versionRegex', e.currentTarget.value)}
              error={errors.versionRegex}
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
            {(f.format === 'docker' || !f.format) && (
              <NumberInput
                label="Docker: untagged manifests older than (days)"
                description="Deletes untagged manifests and unreferenced layers"
                min={1}
                value={f.untaggedOlderThanDays}
                onChange={(v) => set('untaggedOlderThanDays', typeof v === 'number' ? v : '')}
              />
            )}
            <NumberInput
              label="Always keep newest versions"
              description="Per component name, regardless of the other criteria"
              min={0}
              value={f.keepLatest}
              onChange={(v) => set('keepLatest', typeof v === 'number' ? v : '')}
            />
          </SimpleGrid>
          <Switch
            label="Pre-release versions only"
            description="Only versions with a pre-release part, e.g. 1.2.0-rc.1 or 1.0.0.dev3"
            checked={f.prereleaseOnly}
            onChange={(e) => set('prereleaseOnly', e.currentTarget.checked)}
          />
          <Alert
            variant="light"
            color={errors.criteria ? 'orange' : 'blue'}
            icon={errors.criteria ? <IconAlertTriangle size={18} /> : <IconEraser size={18} />}
            p="sm"
          >
            <Text size="sm">
              {errors.criteria ??
                `Deletes ${f.format ? formatLabel(f.format) + ' ' : ''}components ${describeCriteria(criteria).join(', ')}.`}
            </Text>
          </Alert>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!valid} loading={save.isPending}>
              {editing ? 'Save' : 'Create policy'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function PreviewModal({ policy, onClose }: { policy: CleanupPolicy; onClose: () => void }) {
  const repos = useRepositories();
  const options = (repos.data ?? [])
    .filter((r) => r.kind !== 'group' && (!policy.format || r.format === policy.format))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((r) => ({ value: r.name, label: `${r.name} (${formatLabel(r.format)} ${r.kind})` }));
  const [repo, setRepo] = useState<string | null>(policy.repositories?.[0] ?? null);
  const [result, setResult] = useState<CleanupRunResult | null>(null);
  const preview = useMutation({
    mutationFn: (repository: string) =>
      unwrap(api.POST('/cleanup-policies/{name}/preview', { params: { path: { name: policy.name }, query: { repository } } })),
    onSuccess: setResult,
  });
  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>Preview {policy.name}</Text>} size="xl" centered>
      <Stack>
        <Text size="sm" c="dimmed">
          A dry run: shows what the policy would delete from a repository right now. Nothing is deleted.
        </Text>
        <Group align="flex-end">
          <Select
            label="Repository"
            placeholder="Choose a repository"
            data={options}
            value={repo}
            onChange={(v) => {
              setRepo(v);
              setResult(null);
            }}
            searchable
            style={{ flex: 1 }}
            nothingFoundMessage="No matching repositories"
          />
          <Button leftSection={<IconEye size={16} />} disabled={!repo} loading={preview.isPending} onClick={() => repo && preview.mutate(repo)}>
            Preview
          </Button>
        </Group>
        {result && <CleanupResultView result={result} />}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Close
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

export default function CleanupPoliciesPage() {
  const { data, isPending, error, refetch } = useCleanupPolicies();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<CleanupPolicy | 'new' | null>(null);
  const [deleting, setDeleting] = useState<CleanupPolicy | null>(null);
  const [previewing, setPreviewing] = useState<CleanupPolicy | null>(null);
  const del = useMutation({
    mutationFn: (name: string) => unwrapVoid(api.DELETE('/cleanup-policies/{name}', { params: { path: { name } } })),
    onSuccess: () => {
      notifySuccess(`Cleanup policy ${deleting?.name} deleted`);
      setDeleting(null);
      qc.invalidateQueries({ queryKey: qk2.cleanupPolicies });
      qc.invalidateQueries({ queryKey: qk.repositories });
    },
  });

  return (
    <>
      <PageHeader
        title="Cleanup policies"
        description="Rules that delete old or unused components. Attach them to repositories in their settings."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')} disabled={isNotImplemented(error)}>
            Create policy
          </Button>
        }
      />
      <Paper p={0}>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} feature="Cleanup policies" />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={3} cols={4} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<IconEraser size={28} stroke={1.5} />}
            title="No cleanup policies"
            description="For example: delete pre-release versions older than 30 days but always keep the newest 3."
            action={
              <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')}>
                Create policy
              </Button>
            }
          />
        ) : (
          <Table.ScrollContainer minWidth={760}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Format</Table.Th>
                  <Table.Th>Deletes components…</Table.Th>
                  <Table.Th>Repositories</Table.Th>
                  <Table.Th w={120} />
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
                        <Text size="xs" c="dimmed" lineClamp={2} maw={280}>
                          {p.description}
                        </Text>
                      )}
                      <Text size="xs" c="dimmed">
                        updated {formatRelative(p.updatedAt)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {p.format ? (
                        <FormatBadge format={p.format} />
                      ) : (
                        <Text size="sm" c="dimmed">
                          any
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Stack gap={2}>
                        {describeCriteria(p.criteria).map((d) => (
                          <Text key={d} size="xs">
                            • {d}
                          </Text>
                        ))}
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      {(p.repositories ?? []).length === 0 ? (
                        <Text size="sm" c="dimmed">
                          unused
                        </Text>
                      ) : (
                        <Group gap={4}>
                          {(p.repositories ?? []).map((r) => (
                            <Badge
                              key={r}
                              component={Link}
                              to={`/repositories/${r}`}
                              variant="default"
                              tt="none"
                              radius="sm"
                              style={{ cursor: 'pointer' }}
                            >
                              {r}
                            </Badge>
                          ))}
                        </Group>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Group gap={2} wrap="nowrap" justify="flex-end">
                        <Tooltip label="Preview (dry run)">
                          <ActionIcon variant="subtle" color="blue" onClick={() => setPreviewing(p)} aria-label="Preview">
                            <IconEye size={16} />
                          </ActionIcon>
                        </Tooltip>
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
          </Table.ScrollContainer>
        )}
      </Paper>
      <Text size="xs" c="dimmed" mt="sm">
        Policies run on a schedule. To run one now, open a repository that uses it and choose <b>Run now</b> next to
        Cleanup (admins), or{' '}
        <Anchor component="button" size="xs" onClick={() => data?.[0] && setPreviewing(data[0])} disabled={!data?.length}>
          preview a policy
        </Anchor>{' '}
        here.
      </Text>
      {editing && <PolicyModal policy={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      {previewing && <PreviewModal policy={previewing} onClose={() => setPreviewing(null)} />}
      <ConfirmDelete
        opened={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(deleting.name)}
        loading={del.isPending}
        title="Delete cleanup policy"
        confirmText={deleting?.name}
      >
        Delete <b>{deleting?.name}</b>?
        {(deleting?.repositories ?? []).length > 0 && <> It is used by {deleting?.repositories?.join(', ')}.</>}
      </ConfirmDelete>
    </>
  );
}
