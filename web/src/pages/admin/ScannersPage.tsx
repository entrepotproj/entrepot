import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Code,
  Group,
  List,
  Modal,
  NumberInput,
  Paper,
  PasswordInput,
  SegmentedControl,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  TagsInput,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core';
import {
  IconCircleCheck,
  IconCircleX,
  IconInfoCircle,
  IconPencil,
  IconPlayerPlay,
  IconPlus,
  IconRadar2,
  IconTrash,
} from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import {
  api,
  isNotImplemented,
  unwrap,
  unwrapVoid,
  type Scanner,
  type ScannerInput,
  type ScannerTestResult,
  type ScannerType,
} from '../../api/client';
import { qk2, useRepositories, useScanners, useSystemInfo } from '../../api/queries';
import { ScannerTypeBadge } from '../../components/badges';
import { CodeBlock } from '../../components/CodeBlock';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;

const TYPE_HELP: Record<ScannerType, string> = {
  trivy: 'Runs the Trivy CLI, optionally against a Trivy server that holds the vulnerability database. Scans every format, including Docker images and OS packages.',
  grype: 'Runs the Grype CLI on this server. Scans every format, including Docker images and OS packages.',
  webhook: 'Sends scan requests to your own HTTP service, which reports findings back asynchronously.',
};

function WebhookHelp() {
  const { data: info } = useSystemInfo();
  const base = (info?.baseUrl || window.location.origin).replace(/\/+$/, '');
  return (
    <Alert variant="light" color="blue" icon={<IconInfoCircle size={18} />} title="Webhook protocol" p="sm" styles={{ body: { minWidth: 0 } }}>
      <Stack gap={6}>
        <List size="xs" spacing={4} type="ordered">
          <List.Item>
            For each scan job, Entrepot <b>POSTs</b> JSON to the URL with <Code>X-Entrepot-Event: scan</Code> (the Test
            button sends <Code>ping</Code>). With a secret, the body is signed:{' '}
            <Code>X-Entrepot-Signature: sha256=&lt;hex HMAC-SHA256 of body&gt;</Code>. Answer with any 2xx.
          </List.Item>
          <List.Item>
            The service downloads <Code>artifactUrl</Code> (the package file, or an OCI image layout tar when{' '}
            <Code>target</Code> is <Code>image</Code>).
          </List.Item>
          <List.Item>
            Before <Code>expiresAt</Code> it POSTs the results to <Code>callbackUrl</Code> with{' '}
            <Code>Authorization: Bearer &lt;token&gt;</Code>: native findings, a SARIF 2.1 log or a CycloneDX document, or an
            error.
          </List.Item>
        </List>
        <CodeBlock
          title="Request"
          code={`{\n  "type": "scan", "jobId": "…", "scanner": "my-scanner", "repository": "npm-internal",\n  "target": "package",\n  "component": { "id": "…", "name": "lodash", "version": "4.17.20", "format": "npm",\n                 "purl": "pkg:npm/lodash@4.17.20" },\n  "artifactUrl": "${base}/api/v1/scan-jobs/…/artifact?token=…",\n  "callbackUrl": "${base}/api/v1/scan-jobs/…/result",\n  "token": "…", "expiresAt": "2026-01-01T12:15:00Z"\n}`}
        />
        <CodeBlock
          title="Callback"
          code={`{\n  "format": "entrepot",\n  "findings": [{\n    "vulnId": "CVE-2021-23337", "severity": "high",\n    "package": "lodash", "installedVersion": "4.17.20", "fixedVersion": "4.17.21",\n    "title": "Command injection",\n    "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"\n  }]\n}`}
        />
        <Text size="xs" c="dimmed">
          Use <Code>{'{"format":"sarif","document":{…}}'}</Code> or <Code>{'{"format":"cyclonedx","document":{…}}'}</Code> to
          send a scanner's own output, <Code>{'{"error":"…"}'}</Code> to report a failure, or{' '}
          <Code>{'{"unsupported":true}'}</Code> when the artifact type cannot be scanned.
        </Text>
      </Stack>
    </Alert>
  );
}

type Form = {
  name: string;
  type: ScannerType;
  enabled: boolean;
  rescanIntervalHours: number | '';
  binary: string;
  serverUrl: string;
  serverToken: string;
  timeoutSeconds: number | '';
  extraArgs: string[];
  url: string;
  secret: string;
};

function initial(s: Scanner | null): Form {
  const t = s?.type ?? 'trivy';
  const cfg = s ? (t === 'trivy' ? s.trivy : t === 'grype' ? s.grype : undefined) : undefined;
  return {
    name: s?.name ?? '',
    type: t,
    enabled: s?.enabled ?? true,
    rescanIntervalHours: s?.rescanIntervalHours ?? 24,
    binary: cfg?.binary ?? '',
    serverUrl: s?.trivy?.serverUrl ?? '',
    serverToken: '',
    timeoutSeconds: (t === 'webhook' ? s?.webhook?.timeoutSeconds : cfg?.timeoutSeconds) ?? '',
    extraArgs: cfg?.extraArgs ?? [],
    url: s?.webhook?.url ?? '',
    secret: '',
  };
}

function toInput(f: Form): ScannerInput {
  const timeout = f.timeoutSeconds === '' ? undefined : f.timeoutSeconds;
  const input: ScannerInput = {
    name: f.name.trim(),
    type: f.type,
    enabled: f.enabled,
    rescanIntervalHours: f.rescanIntervalHours === '' ? 0 : f.rescanIntervalHours,
  };
  if (f.type === 'trivy') {
    input.trivy = {
      binary: f.binary.trim() || undefined,
      serverUrl: f.serverUrl.trim() || undefined,
      serverToken: f.serverToken || undefined,
      timeoutSeconds: timeout,
      extraArgs: f.extraArgs,
    };
  } else if (f.type === 'grype') {
    input.grype = { binary: f.binary.trim() || undefined, timeoutSeconds: timeout, extraArgs: f.extraArgs };
  } else {
    input.webhook = { url: f.url.trim(), secret: f.secret || undefined, timeoutSeconds: timeout };
  }
  return input;
}

function ScannerModal({ scanner, onClose }: { scanner: Scanner | null; onClose: () => void }) {
  const editing = !!scanner;
  const qc = useQueryClient();
  const [f, setF] = useState<Form>(() => initial(scanner));
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF((p) => ({ ...p, [k]: v }));
  const [touched, setTouched] = useState(false);

  const save = useMutation({
    mutationFn: (body: ScannerInput) =>
      editing
        ? unwrap(api.PUT('/scanners/{name}', { params: { path: { name: body.name } }, body }))
        : unwrap(api.POST('/scanners', { body })),
    onSuccess: (s) => {
      qc.invalidateQueries({ queryKey: qk2.scanners });
      notifySuccess(`Scanner ${s.name} saved`);
      onClose();
    },
  });

  const errors = {
    name: !NAME_RE.test(f.name) ? "Lowercase letters, digits, '.', '_' and '-'" : null,
    url: f.type === 'webhook' && !/^https?:\/\/.+/.test(f.url.trim()) ? 'An http(s) URL is required' : null,
    serverUrl: f.type === 'trivy' && f.serverUrl.trim() && !/^https?:\/\/.+/.test(f.serverUrl.trim()) ? 'Must be an http(s) URL' : null,
  };
  const valid = Object.values(errors).every((e) => !e);
  const err = (k: keyof typeof errors) => (touched ? errors[k] : null);
  const keep = editing ? 'Leave blank to keep the stored value' : undefined;

  return (
    <Modal
      opened
      onClose={onClose}
      title={<Text fw={600}>{editing ? `Edit scanner ${scanner.name}` : 'Add scanner'}</Text>}
      size="xl"
      centered
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setTouched(true);
          if (valid) save.mutate(toInput(f));
        }}
      >
        <Stack>
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <TextInput
              label="Name"
              description="Referenced by repositories' scan settings"
              placeholder="trivy"
              value={f.name}
              onChange={(e) => set('name', e.currentTarget.value.toLowerCase())}
              disabled={editing}
              error={err('name')}
              required
              data-autofocus
            />
            <div>
              <Text size="sm" fw={500} mb={4}>
                Type
              </Text>
              <SegmentedControl
                fullWidth
                value={f.type}
                onChange={(v) => set('type', v as ScannerType)}
                disabled={editing}
                data={[
                  { value: 'trivy', label: 'Trivy' },
                  { value: 'grype', label: 'Grype' },
                  { value: 'webhook', label: 'Webhook' },
                ]}
              />
            </div>
          </SimpleGrid>
          <Text size="xs" c="dimmed" mt={-8}>
            {TYPE_HELP[f.type]}
          </Text>

          {f.type === 'trivy' && (
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label="Server URL"
                description="Client/server mode (recommended): one shared vulnerability DB"
                placeholder="http://trivy.security.svc:4954"
                value={f.serverUrl}
                onChange={(e) => set('serverUrl', e.currentTarget.value)}
                error={err('serverUrl')}
              />
              <PasswordInput
                label="Server token"
                description={keep ?? 'Optional; sent as the Trivy-Token header'}
                placeholder={editing ? '••••••••' : undefined}
                value={f.serverToken}
                onChange={(e) => set('serverToken', e.currentTarget.value)}
                autoComplete="new-password"
              />
            </SimpleGrid>
          )}
          {f.type === 'webhook' && (
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label="URL"
                description="Receives scan requests"
                placeholder="https://scanner.example.com/entrepot"
                value={f.url}
                onChange={(e) => set('url', e.currentTarget.value)}
                error={err('url')}
                required
              />
              <PasswordInput
                label="Secret"
                description={keep ?? 'HMAC-SHA256 key for X-Entrepot-Signature (recommended)'}
                placeholder={editing ? '••••••••' : undefined}
                value={f.secret}
                onChange={(e) => set('secret', e.currentTarget.value)}
                autoComplete="new-password"
              />
            </SimpleGrid>
          )}
          <SimpleGrid cols={{ base: 1, sm: f.type === 'webhook' ? 2 : 3 }}>
            {f.type !== 'webhook' && (
              <TextInput
                label="Binary"
                description={`Path to the CLI (default "${f.type}")`}
                placeholder={f.type}
                value={f.binary}
                onChange={(e) => set('binary', e.currentTarget.value)}
              />
            )}
            <NumberInput
              label="Timeout (seconds)"
              description={f.type === 'webhook' ? 'Time allowed for the callback (default 900)' : 'Per scan'}
              placeholder={f.type === 'webhook' ? '900' : '300'}
              min={1}
              value={f.timeoutSeconds}
              onChange={(v) => set('timeoutSeconds', typeof v === 'number' ? v : '')}
            />
            <NumberInput
              label="Rescan interval (hours)"
              description="Re-scan components for new vulnerabilities; 0 = never"
              min={0}
              value={f.rescanIntervalHours}
              onChange={(v) => set('rescanIntervalHours', typeof v === 'number' ? v : '')}
            />
          </SimpleGrid>
          {f.type !== 'webhook' && (
            <TagsInput
              label="Extra arguments"
              description={
                f.type === 'trivy' ? (
                  <>
                    Appended to the command line, e.g. <Code fz={11}>--ignore-unfixed</Code>, <Code fz={11}>--skip-db-update</Code>
                  </>
                ) : (
                  <>
                    Appended to the command line, e.g. <Code fz={11}>--only-fixed</Code>
                  </>
                )
              }
              placeholder="Type an argument and press Enter"
              value={f.extraArgs}
              onChange={(v) => set('extraArgs', v)}
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
          )}
          <Switch
            label="Enabled"
            description="Disabled scanners are skipped; their previous results are kept"
            checked={f.enabled}
            onChange={(e) => set('enabled', e.currentTarget.checked)}
          />
          {f.type === 'webhook' && <WebhookHelp />}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending}>
              {editing ? 'Save' : 'Add scanner'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function target(s: Scanner): string {
  if (s.type === 'webhook') return s.webhook?.url ?? '';
  if (s.type === 'trivy') return s.trivy?.serverUrl || s.trivy?.binary || 'trivy';
  return s.grype?.binary || 'grype';
}

function TestResult({ r }: { r?: ScannerTestResult | 'pending' }) {
  if (!r) return null;
  if (r === 'pending') {
    return (
      <Badge variant="light" color="blue" tt="none" radius="sm">
        testing…
      </Badge>
    );
  }
  return (
    <Stack gap={2} maw={240}>
    <Tooltip label={r.message} multiline maw={420} withArrow>
      <Badge
        variant="light"
        color={r.ok ? 'teal' : 'red'}
        leftSection={r.ok ? <IconCircleCheck size={12} /> : <IconCircleX size={12} />}
        tt="none"
        radius="sm"
        style={{ maxWidth: 220 }}
      >
        {r.ok ? (r.version ? `OK · ${r.version}` : 'OK') : 'Failed'}
      </Badge>
    </Tooltip>
      {!r.ok && r.message && (
        <Text size="xs" c="dimmed" lineClamp={2} title={r.message}>
          {r.message}
        </Text>
      )}
    </Stack>
  );
}

export default function ScannersPage() {
  const { data, isPending, error, refetch } = useScanners();
  const repos = useRepositories();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Scanner | 'new' | null>(null);
  const [deleting, setDeleting] = useState<Scanner | null>(null);
  const [tests, setTests] = useState<Record<string, ScannerTestResult | 'pending'>>({});

  const del = useMutation({
    mutationFn: (name: string) => unwrapVoid(api.DELETE('/scanners/{name}', { params: { path: { name } } })),
    onSuccess: () => {
      notifySuccess(`Scanner ${deleting?.name} deleted`);
      setDeleting(null);
      qc.invalidateQueries({ queryKey: qk2.scanners });
    },
  });
  const test = useMutation({
    mutationFn: (name: string) => unwrap(api.POST('/scanners/{name}/test', { params: { path: { name } } })),
    onMutate: (name) => setTests((t) => ({ ...t, [name]: 'pending' })),
    onSuccess: (r, name) => {
      setTests((t) => ({ ...t, [name]: r }));
      if (r.ok) notifySuccess(r.message || `Scanner ${name} is reachable`, r.version ? `${name} ${r.version}` : name);
    },
    onError: (_e, name) =>
      setTests((t) => {
        const n = { ...t };
        delete n[name];
        return n;
      }),
  });

  const usedBy = (name: string) => (repos.data ?? []).filter((r) => r.scan?.scanners?.includes(name)).map((r) => r.name);
  const unavailable = isNotImplemented(error);

  return (
    <>
      <PageHeader
        title="Scanners"
        description="Vulnerability scanners that repositories can use to scan their components."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')} disabled={unavailable}>
            Add scanner
          </Button>
        }
      />
      <Paper p={0}>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} feature="Vulnerability scanning" />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={3} cols={5} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<IconRadar2 size={28} stroke={1.5} />}
            title="No scanners"
            description="Add a Trivy or Grype scanner, or connect your own scanning service with a webhook. Then select it in a repository's scanning settings."
            action={
              <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')}>
                Add scanner
              </Button>
            }
          />
        ) : (
          <Table.ScrollContainer minWidth={760}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Type</Table.Th>
                  <Table.Th>Target</Table.Th>
                  <Table.Th>Rescan</Table.Th>
                  <Table.Th>Used by</Table.Th>
                  <Table.Th>Test</Table.Th>
                  <Table.Th w={120} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.map((s) => {
                  const used = usedBy(s.name);
                  return (
                    <Table.Tr key={s.name} style={s.enabled ? undefined : { opacity: 0.65 }}>
                      <Table.Td>
                        <Group gap={6} wrap="nowrap">
                          <Text size="sm" fw={600}>
                            {s.name}
                          </Text>
                          {!s.enabled && (
                            <Badge size="xs" variant="outline" color="gray" tt="none">
                              disabled
                            </Badge>
                          )}
                        </Group>
                        <Text size="xs" c="dimmed">
                          updated {formatRelative(s.updatedAt)}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <ScannerTypeBadge type={s.type} />
                      </Table.Td>
                      <Table.Td>
                        <Text size="xs" ff="monospace" truncate="end" maw={260} title={target(s)}>
                          {target(s)}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" c={s.rescanIntervalHours ? undefined : 'dimmed'}>
                          {s.rescanIntervalHours ? `every ${s.rescanIntervalHours} h` : 'never'}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" c={used.length ? undefined : 'dimmed'} title={used.join(', ')}>
                          {used.length === 0 ? '—' : used.length <= 2 ? used.join(', ') : `${used.length} repositories`}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <TestResult r={tests[s.name]} />
                      </Table.Td>
                      <Table.Td>
                        <Group gap={2} wrap="nowrap" justify="flex-end">
                          <Tooltip label="Test connection">
                            <ActionIcon
                              variant="subtle"
                              color="teal"
                              onClick={() => test.mutate(s.name)}
                              loading={tests[s.name] === 'pending'}
                              aria-label="Test"
                            >
                              <IconPlayerPlay size={16} />
                            </ActionIcon>
                          </Tooltip>
                          <Tooltip label="Edit">
                            <ActionIcon variant="subtle" color="gray" onClick={() => setEditing(s)} aria-label="Edit">
                              <IconPencil size={16} />
                            </ActionIcon>
                          </Tooltip>
                          <Tooltip label="Delete">
                            <ActionIcon variant="subtle" color="red" onClick={() => setDeleting(s)} aria-label="Delete">
                              <IconTrash size={16} />
                            </ActionIcon>
                          </Tooltip>
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      {editing && <ScannerModal scanner={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      <ConfirmDelete
        opened={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(deleting.name)}
        loading={del.isPending}
        title="Delete scanner"
        confirmText={deleting?.name}
      >
        Delete scanner <b>{deleting?.name}</b>?
        {deleting && usedBy(deleting.name).length > 0 && (
          <> It is used by {usedBy(deleting.name).join(', ')}; those repositories stop scanning with it.</>
        )}{' '}
        Existing results are removed.
      </ConfirmDelete>
    </>
  );
}
