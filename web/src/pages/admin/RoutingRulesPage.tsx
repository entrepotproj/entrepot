import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  Paper,
  SegmentedControl,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
  Tooltip,
  UnstyledButton,
} from '@mantine/core';
import {
  IconBan,
  IconCircleCheck,
  IconFlask,
  IconInfoCircle,
  IconPencil,
  IconPlus,
  IconRoute,
  IconTrash,
  IconX,
} from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router';
import {
  api,
  isNotImplemented,
  unwrap,
  unwrapVoid,
  type RoutingRule,
  type RoutingRuleInput,
  type RoutingTestResult,
} from '../../api/client';
import { qk, qk2, useRoutingRules } from '../../api/queries';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
type Mode = RoutingRuleInput['mode'];

const EXAMPLES: { re: string; help: string }[] = [
  { re: '^@acme/', help: 'npm scope @acme' },
  { re: '^acme-', help: 'names starting with acme-' },
  { re: '^acme[-_.]', help: 'PyPI acme-*, acme_*, acme.*' },
  { re: '^charts/internal-', help: 'Helm/raw path prefix' },
  { re: '^library/', help: 'Docker Hub official images' },
];

const MODE_HELP: Record<Mode, string> = {
  allow: 'Only requests matching a matcher are fetched from the remote; everything else is served from cache only.',
  block: 'Requests matching a matcher are never fetched from the remote. Use it to keep internal package names off public registries.',
};

function regexError(s: string): string | null {
  try {
    new RegExp(s);
    return null;
  } catch (e) {
    return e instanceof Error ? e.message.replace(/^Invalid regular expression: /, '') : 'Invalid';
  }
}

/** Local evaluation of a rule (JS regex; the server uses Go RE2, which is nearly identical for simple patterns). */
function evaluate(mode: Mode, matchers: string[], path: string): RoutingTestResult {
  const matched = matchers.find((m) => {
    try {
      return new RegExp(m).test(path);
    } catch {
      return false;
    }
  });
  return { allowed: mode === 'allow' ? !!matched : !matched, matched };
}

function Verdict({ result, mode }: { result: RoutingTestResult; mode: Mode }) {
  return (
    <Alert
      variant="light"
      color={result.allowed ? 'teal' : 'red'}
      icon={result.allowed ? <IconCircleCheck size={18} /> : <IconBan size={18} />}
      p="sm"
    >
      <Text size="sm" fw={600}>
        {result.allowed ? 'Allowed — may be fetched upstream' : 'Blocked — never fetched upstream'}
      </Text>
      <Text size="xs" c="dimmed">
        {result.matched ? (
          <>
            Matched <Code fz={11}>{result.matched}</Code>
          </>
        ) : mode === 'allow' ? (
          'No matcher matched (allow mode blocks everything else).'
        ) : (
          'No matcher matched.'
        )}
      </Text>
    </Alert>
  );
}

function RuleModal({ rule, onClose }: { rule: RoutingRule | null; onClose: () => void }) {
  const editing = !!rule;
  const qc = useQueryClient();
  const [name, setName] = useState(rule?.name ?? '');
  const [description, setDescription] = useState(rule?.description ?? '');
  const [mode, setMode] = useState<Mode>(rule?.mode ?? 'block');
  const [matchers, setMatchers] = useState<string[]>(rule?.matchers.length ? rule.matchers : ['']);
  const [tryPath, setTryPath] = useState('');

  const filled = matchers.map((m) => m.trim()).filter(Boolean);
  const regexErrors = matchers.map((m) => (m.trim() ? regexError(m.trim()) : null));
  const valid = NAME_RE.test(name) && filled.length > 0 && regexErrors.every((e) => !e);

  const save = useMutation({
    mutationFn: (body: RoutingRuleInput) =>
      editing
        ? unwrap(api.PUT('/routing-rules/{name}', { params: { path: { name: body.name } }, body }))
        : unwrap(api.POST('/routing-rules', { body })),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: qk2.routingRules });
      notifySuccess(`Routing rule ${r.name} saved`);
      onClose();
    },
  });

  const setAt = (i: number, v: string) => setMatchers((ms) => ms.map((m, j) => (j === i ? v : m)));
  const addExample = (re: string) =>
    setMatchers((ms) => (ms.includes(re) ? ms : ms.length === 1 && !ms[0].trim() ? [re] : [...ms, re]));

  return (
    <Modal
      opened
      onClose={onClose}
      title={<Text fw={600}>{editing ? `Edit routing rule ${rule.name}` : 'Create routing rule'}</Text>}
      size="xl"
      centered
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) save.mutate({ name: name.trim(), description, mode, matchers: filled });
        }}
      >
        <Stack>
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <TextInput
              label="Name"
              placeholder="internal-names"
              value={name}
              onChange={(e) => setName(e.currentTarget.value.toLowerCase())}
              disabled={editing}
              error={name && !NAME_RE.test(name) ? "Lowercase letters, digits, '.', '_' and '-'" : null}
              required
              data-autofocus
            />
            <div>
              <Text size="sm" fw={500} mb={4}>
                Mode
              </Text>
              <SegmentedControl
                fullWidth
                value={mode}
                onChange={(v) => setMode(v as Mode)}
                data={[
                  { value: 'block', label: 'Block matching' },
                  { value: 'allow', label: 'Allow only matching' },
                ]}
              />
            </div>
          </SimpleGrid>
          <Text size="xs" c="dimmed" mt={-8}>
            {MODE_HELP[mode]}
          </Text>
          <Textarea label="Description" autosize minRows={1} value={description} onChange={(e) => setDescription(e.currentTarget.value)} />
          <div>
            <Text size="sm" fw={500}>
              Matchers
            </Text>
            <Text size="xs" c="dimmed" mb={8}>
              Regular expressions over the package name or request path. Anchor them with <Code fz={11}>^</Code> to match
              prefixes.
            </Text>
            <Stack gap={6}>
              {matchers.map((m, i) => (
                <Group key={i} gap={6} wrap="nowrap" align="flex-start">
                  <TextInput
                    placeholder="^@acme/"
                    value={m}
                    onChange={(e) => setAt(i, e.currentTarget.value)}
                    error={regexErrors[i]}
                    style={{ flex: 1 }}
                    styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
                  />
                  <ActionIcon
                    variant="subtle"
                    color="gray"
                    size="lg"
                    onClick={() => setMatchers((ms) => (ms.length === 1 ? [''] : ms.filter((_, j) => j !== i)))}
                    aria-label="Remove matcher"
                  >
                    <IconX size={16} />
                  </ActionIcon>
                </Group>
              ))}
            </Stack>
            <Group gap={6} mt={8}>
              <Button variant="subtle" size="xs" leftSection={<IconPlus size={14} />} onClick={() => setMatchers((ms) => [...ms, ''])}>
                Add matcher
              </Button>
              <Text size="xs" c="dimmed">
                Examples:
              </Text>
              {EXAMPLES.map((ex) => (
                <Tooltip key={ex.re} label={ex.help} withArrow>
                  <UnstyledButton onClick={() => addExample(ex.re)}>
                    <Badge variant="outline" color="gray" tt="none" radius="sm" ff="monospace" style={{ cursor: 'pointer' }}>
                      {ex.re}
                    </Badge>
                  </UnstyledButton>
                </Tooltip>
              ))}
            </Group>
          </div>
          <Paper p="sm" bg="var(--mantine-color-default-hover)">
            <TextInput
              label="Try it"
              description="Checked locally as you type; use Test on the rules list to check against the server."
              placeholder="@acme/widgets"
              leftSection={<IconFlask size={16} />}
              value={tryPath}
              onChange={(e) => setTryPath(e.currentTarget.value)}
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
            {tryPath.trim() && (
              <div style={{ marginTop: 8 }}>
                <Verdict result={evaluate(mode, filled, tryPath.trim())} mode={mode} />
              </div>
            )}
          </Paper>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!valid} loading={save.isPending}>
              {editing ? 'Save' : 'Create rule'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function TestModal({ rule, onClose }: { rule: RoutingRule; onClose: () => void }) {
  const [path, setPath] = useState('');
  const [result, setResult] = useState<RoutingTestResult | null>(null);
  const test = useMutation({
    mutationFn: (p: string) => unwrap(api.POST('/routing-rules/{name}/test', { params: { path: { name: rule.name } }, body: { path: p } })),
    onSuccess: setResult,
  });
  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>Test {rule.name}</Text>} size="lg" centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (path.trim()) test.mutate(path.trim());
        }}
      >
        <Stack>
          <Group gap={6}>
            <ModeBadge mode={rule.mode} />
            {rule.matchers.map((m) => (
              <Code key={m}>{m}</Code>
            ))}
          </Group>
          <Group align="flex-end" wrap="nowrap">
            <TextInput
              label="Package name or path"
              placeholder="@acme/widgets"
              value={path}
              onChange={(e) => {
                setPath(e.currentTarget.value);
                setResult(null);
              }}
              style={{ flex: 1 }}
              data-autofocus
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
            <Button type="submit" leftSection={<IconFlask size={16} />} loading={test.isPending} disabled={!path.trim()}>
              Test
            </Button>
          </Group>
          {result && <Verdict result={result} mode={rule.mode} />}
        </Stack>
      </form>
    </Modal>
  );
}

function ModeBadge({ mode }: { mode: Mode }) {
  return (
    <Badge
      variant="light"
      color={mode === 'allow' ? 'teal' : 'red'}
      leftSection={mode === 'allow' ? <IconCircleCheck size={12} /> : <IconBan size={12} />}
      tt="none"
      radius="sm"
    >
      {mode === 'allow' ? 'allow only' : 'block'}
    </Badge>
  );
}

export default function RoutingRulesPage() {
  const { data, isPending, error, refetch } = useRoutingRules();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<RoutingRule | 'new' | null>(null);
  const [deleting, setDeleting] = useState<RoutingRule | null>(null);
  const [testing, setTesting] = useState<RoutingRule | null>(null);
  const del = useMutation({
    mutationFn: (name: string) => unwrapVoid(api.DELETE('/routing-rules/{name}', { params: { path: { name } } })),
    onSuccess: () => {
      notifySuccess(`Routing rule ${deleting?.name} deleted`);
      setDeleting(null);
      qc.invalidateQueries({ queryKey: qk2.routingRules });
      qc.invalidateQueries({ queryKey: qk.repositories });
    },
    onError: () => setDeleting(null),
  });

  return (
    <>
      <PageHeader
        title="Routing rules"
        description="Control which packages proxy repositories may fetch from their remote."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')} disabled={isNotImplemented(error)}>
            Create rule
          </Button>
        }
      />
      <Stack gap="md">
        <Paper p={0}>
          {error ? (
            <div style={{ padding: 12 }}>
              <QueryError error={error} retry={refetch} feature="Routing rules" />
            </div>
          ) : isPending ? (
            <TableSkeleton rows={3} cols={4} />
          ) : data.length === 0 ? (
            <EmptyState
              icon={<IconRoute size={28} stroke={1.5} />}
              title="No routing rules"
              description="For example, block ^@acme/ on your npmjs proxy so internal package names are never requested from the public registry."
              action={
                <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')}>
                  Create rule
                </Button>
              }
            />
          ) : (
            <Table.ScrollContainer minWidth={720}>
              <Table>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Name</Table.Th>
                    <Table.Th>Mode</Table.Th>
                    <Table.Th>Matchers</Table.Th>
                    <Table.Th>Used by</Table.Th>
                    <Table.Th w={120} />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {data.map((r) => (
                    <Table.Tr key={r.name}>
                      <Table.Td>
                        <Text size="sm" fw={600}>
                          {r.name}
                        </Text>
                        {r.description && (
                          <Text size="xs" c="dimmed" lineClamp={2} maw={280}>
                            {r.description}
                          </Text>
                        )}
                        <Text size="xs" c="dimmed">
                          updated {formatRelative(r.updatedAt)}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <ModeBadge mode={r.mode} />
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4}>
                          {r.matchers.map((m) => (
                            <Code key={m}>{m}</Code>
                          ))}
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        {(r.repositories ?? []).length === 0 ? (
                          <Text size="sm" c="dimmed">
                            unused
                          </Text>
                        ) : (
                          <Group gap={4}>
                            {(r.repositories ?? []).map((name) => (
                              <Badge
                                key={name}
                                component={Link}
                                to={`/repositories/${name}`}
                                variant="default"
                                tt="none"
                                radius="sm"
                                style={{ cursor: 'pointer' }}
                              >
                                {name}
                              </Badge>
                            ))}
                          </Group>
                        )}
                      </Table.Td>
                      <Table.Td>
                        <Group gap={2} wrap="nowrap" justify="flex-end">
                          <Tooltip label="Test a path">
                            <ActionIcon variant="subtle" color="blue" onClick={() => setTesting(r)} aria-label="Test">
                              <IconFlask size={16} />
                            </ActionIcon>
                          </Tooltip>
                          <Tooltip label="Edit">
                            <ActionIcon variant="subtle" color="gray" onClick={() => setEditing(r)} aria-label="Edit">
                              <IconPencil size={16} />
                            </ActionIcon>
                          </Tooltip>
                          <Tooltip label={(r.repositories ?? []).length ? 'In use — remove it from repositories first' : 'Delete'}>
                            <ActionIcon variant="subtle" color="red" onClick={() => setDeleting(r)} aria-label="Delete">
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
        <Alert variant="light" color="blue" icon={<IconInfoCircle size={18} />} title="Routing rules and dependency confusion">
          <Text size="sm">
            Attach a rule to a proxy repository under its <b>Proxy → Routing</b> settings. A <b>block</b> rule such as{' '}
            <Code>^@acme/</Code> on an npmjs proxy guarantees your internal names are never resolved from the public
            registry, even if someone publishes them there. Groups add a second layer with <b>Prefer hosted packages</b>.
          </Text>
        </Alert>
      </Stack>
      {editing && <RuleModal rule={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      {testing && <TestModal rule={testing} onClose={() => setTesting(null)} />}
      <ConfirmDelete
        opened={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(deleting.name)}
        loading={del.isPending}
        title="Delete routing rule"
        confirmText={deleting?.name}
      >
        Delete <b>{deleting?.name}</b>?
        {(deleting?.repositories ?? []).length > 0 && (
          <> It is still used by {deleting?.repositories?.join(', ')}; the server will refuse until it is removed from them.</>
        )}
      </ConfirmDelete>
    </>
  );
}
