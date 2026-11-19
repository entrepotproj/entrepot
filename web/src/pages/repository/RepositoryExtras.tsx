import {
  Alert,
  Anchor,
  Badge,
  Button,
  Code,
  CopyButton,
  Group,
  Modal,
  Paper,
  PasswordInput,
  ScrollArea,
  Select,
  SimpleGrid,
  Skeleton,
  Stack,
  Table,
  Text,
  Textarea,
  Title,
  Tooltip,
} from '@mantine/core';
import {
  IconAlertTriangle,
  IconCheck,
  IconCopy,
  IconDownload,
  IconEraser,
  IconFileImport,
  IconInfoCircle,
  IconKey,
  IconRotate,
  IconShieldCheck,
} from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import {
  api,
  isNotImplemented,
  unwrap,
  type CleanupRunResult,
  type Repository,
  type SigningKeyImport,
} from '../../api/client';
import { qk, qk2, useSigningKey } from '../../api/queries';
import { SeverityBadge } from '../../components/badges';
import { CopyText } from '../../components/CodeBlock';
import { QueryError } from '../../components/states';
import { formatBytes, formatDate, formatNumber, formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

const PREFER_HOSTED_FORMATS = ['npm', 'pypi', 'helm'];

const modeColors: Record<string, string> = { off: 'gray', warn: 'yellow', quarantine: 'red' };

function NameBadges({ names, to }: { names: string[]; to?: string }) {
  return (
    <Group gap={4} justify="flex-end">
      {names.map((n) =>
        to ? (
          <Badge key={n} component={Link} to={to} variant="default" tt="none" radius="sm" style={{ cursor: 'pointer' }}>
            {n}
          </Badge>
        ) : (
          <Badge key={n} variant="default" tt="none" radius="sm">
            {n}
          </Badge>
        ),
      )}
    </Group>
  );
}

/** Extra rows for the repository details panel (Phase 2 settings). */
export function settingsRows(r: Repository, canAdmin: boolean, onRunCleanup: () => void): [string, ReactNode][] {
  const rows: [string, ReactNode][] = [];
  if (r.hosted?.apt) {
    const ds = r.hosted.apt.distributions ?? [];
    rows.push([
      'Distributions',
      ds.length === 0 ? (
        <Text size="sm">stable / main (default)</Text>
      ) : (
        <Stack gap={2} align="flex-end">
          {ds.map((d) => (
            <Text key={d.name} size="sm" ff="monospace">
              {d.name}{' '}
              <Text span size="xs" c="dimmed" ff="monospace">
                {(d.components ?? []).join(',') || 'main'} · {(d.architectures ?? []).join(',') || 'any'}
              </Text>
            </Text>
          ))}
        </Stack>
      ),
    ]);
  }
  if (r.hosted?.yum) {
    rows.push(['Repodata depth', <Text size="sm">{r.hosted.yum.repodataDepth ?? 0}</Text>]);
  }
  if (r.proxy && r.kind === 'proxy') {
    rows.push([
      'Routing rule',
      r.proxy.routingRule ? (
        <NameBadges names={[r.proxy.routingRule]} to={canAdmin ? '/admin/routing-rules' : undefined} />
      ) : (
        <Text size="sm" c="dimmed">
          none
        </Text>
      ),
    ]);
  }
  if (r.group && PREFER_HOSTED_FORMATS.includes(r.format)) {
    const on = r.group.preferHosted ?? true;
    rows.push([
      'Prefer hosted',
      <Tooltip label="Dependency-confusion protection: names in hosted members are never served from proxies" withArrow>
        <Badge
          variant="light"
          color={on ? 'teal' : 'orange'}
          leftSection={on ? <IconShieldCheck size={12} /> : <IconAlertTriangle size={12} />}
          tt="none"
          radius="sm"
        >
          {on ? 'On' : 'Off'}
        </Badge>
      </Tooltip>,
    ]);
  }
  if (r.kind !== 'group') {
    const sc = r.scan;
    const enabled = !!sc && (sc.scanners?.length ?? 0) > 0 && sc.mode !== 'off';
    rows.push([
      'Scanning',
      enabled ? (
        <Stack gap={4} align="flex-end">
          <Group gap={4} justify="flex-end">
            <Badge variant="light" color={modeColors[sc.mode ?? 'warn']} tt="none" radius="sm">
              {sc.mode ?? 'warn'}
            </Badge>
            <Text size="xs" c="dimmed">
              threshold
            </Text>
            <SeverityBadge severity={sc.severityThreshold ?? 'high'} size="sm" />
          </Group>
          <NameBadges names={sc.scanners ?? []} to={canAdmin ? '/admin/scanners' : undefined} />
          <Text size="xs" c="dimmed">
            {[
              r.kind !== 'proxy' && sc.onUpload !== false && 'on upload',
              r.kind !== 'hosted' && sc.onProxyFetch !== false && 'on proxy fetch',
              sc.blockUntilScanned && sc.mode === 'quarantine' && 'blocks until scanned',
              sc.distro && `distro ${sc.distro}`,
            ]
              .filter(Boolean)
              .join(' · ')}
          </Text>
        </Stack>
      ) : (
        <Text size="sm" c="dimmed">
          {sc && (sc.scanners?.length ?? 0) > 0 ? 'off' : 'not configured'}
        </Text>
      ),
    ]);
    const pols = r.cleanup?.policies ?? [];
    rows.push([
      'Cleanup',
      <Group gap={6} justify="flex-end">
        {pols.length === 0 ? (
          <Text size="sm" c="dimmed">
            no policies
          </Text>
        ) : (
          <NameBadges names={pols} to={canAdmin ? '/admin/cleanup-policies' : undefined} />
        )}
        {canAdmin && pols.length > 0 && (
          <Button size="compact-xs" variant="light" leftSection={<IconEraser size={12} />} onClick={onRunCleanup}>
            Run now
          </Button>
        )}
      </Group>,
    ]);
  }
  return rows;
}

function fingerprintGroups(fp: string): string {
  return fp
    .replace(/\s+/g, '')
    .toUpperCase()
    .replace(/(.{4})/g, '$1 ')
    .trim();
}

function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/pgp-keys' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Signing key of a hosted Apt/Yum repository. */
export function SigningKeyPanel({ repository }: { repository: Repository }) {
  const name = repository.name;
  const canAdmin = repository.permissions.includes('admin');
  const { data: key, isPending, error, refetch } = useSigningKey(name);
  const qc = useQueryClient();
  const [rotating, setRotating] = useState(false);
  const [importing, setImporting] = useState(false);

  const rotate = useMutation({
    mutationFn: () => unwrap(api.POST('/repositories/{name}/signing-key/rotate', { params: { path: { name } } })),
    onSuccess: (k) => {
      qc.setQueryData(qk2.signingKey(name), k);
      setRotating(false);
      notifySuccess(`New key ${fingerprintGroups(k.fingerprint).slice(-19)}`, 'Signing key rotated');
    },
  });

  return (
    <Paper p="lg">
      <Group justify="space-between" mb="sm" wrap="wrap" gap="xs">
        <div>
          <Title order={5}>
            <Group gap={6} component="span">
              <IconKey size={18} /> Signing key
            </Group>
          </Title>
          <Text size="sm" c="dimmed">
            {repository.format === 'apt' ? 'Release / InRelease' : 'repomd.xml'} metadata is signed with this OpenPGP key.
            Clients must trust its public key.
          </Text>
        </div>
        {canAdmin && key && (
          <Group gap="xs">
            <Button size="xs" variant="default" leftSection={<IconFileImport size={14} />} onClick={() => setImporting(true)}>
              Import
            </Button>
            <Button size="xs" variant="light" color="orange" leftSection={<IconRotate size={14} />} onClick={() => setRotating(true)}>
              Rotate
            </Button>
          </Group>
        )}
      </Group>
      {error ? (
        <QueryError error={error} retry={refetch} feature="Repository signing" compact />
      ) : isPending ? (
        <Stack gap="xs">
          <Skeleton height={16} width="60%" />
          <Skeleton height={16} width="40%" />
        </Stack>
      ) : (
        <Stack gap="sm">
          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
            <div>
              <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
                Fingerprint
              </Text>
              <Text ff="monospace" size="sm" style={{ wordBreak: 'break-word' }}>
                {fingerprintGroups(key.fingerprint)}
              </Text>
            </div>
            <div>
              <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
                Created
              </Text>
              <Text size="sm" title={formatDate(key.createdAt)}>
                {formatDate(key.createdAt)}{' '}
                <Text span size="xs" c="dimmed">
                  ({formatRelative(key.createdAt)})
                </Text>
                {key.algorithm && (
                  <Badge ml={6} size="xs" variant="default" tt="none" radius="sm">
                    {key.algorithm}
                  </Badge>
                )}
              </Text>
            </div>
          </SimpleGrid>
          <div>
            <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
              Public key URL
            </Text>
            <CopyText value={key.url} maw="100%" />
          </div>
          <Group gap="xs">
            <CopyButton value={key.publicKey} timeout={1500}>
              {({ copied, copy }) => (
                <Button
                  size="xs"
                  variant="default"
                  color={copied ? 'teal' : undefined}
                  leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
                  onClick={copy}
                >
                  {copied ? 'Copied' : 'Copy public key'}
                </Button>
              )}
            </CopyButton>
            <Button
              size="xs"
              variant="default"
              leftSection={<IconDownload size={14} />}
              onClick={() => downloadText(`entrepot-${name}.asc`, key.publicKey)}
            >
              Download
            </Button>
          </Group>
        </Stack>
      )}

      <Modal opened={rotating} onClose={() => setRotating(false)} title={<Text fw={600}>Rotate signing key</Text>} centered>
        <Stack>
          <Text size="sm">
            A new key is generated and all metadata of <b>{name}</b> is re-signed. Clients that trust the current key will
            fail to update until they install the new public key.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setRotating(false)}>
              Cancel
            </Button>
            <Button color="orange" loading={rotate.isPending} leftSection={<IconRotate size={16} />} onClick={() => rotate.mutate()}>
              Rotate key
            </Button>
          </Group>
        </Stack>
      </Modal>
      {importing && <ImportKeyModal name={name} onClose={() => setImporting(false)} />}
    </Paper>
  );
}

function ImportKeyModal({ name, onClose }: { name: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [privateKey, setPrivateKey] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const imp = useMutation({
    mutationFn: (body: SigningKeyImport) =>
      unwrap(api.PUT('/repositories/{name}/signing-key', { params: { path: { name } }, body })),
    onSuccess: (k) => {
      qc.setQueryData(qk2.signingKey(name), k);
      notifySuccess(`Imported key ${fingerprintGroups(k.fingerprint).slice(-19)}`, 'Signing key replaced');
      onClose();
    },
  });
  const looksArmored = /-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(privateKey);
  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>Import signing key</Text>} size="lg" centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (looksArmored) imp.mutate({ privateKey, passphrase: passphrase || undefined });
        }}
      >
        <Stack>
          <Text size="sm" c="dimmed">
            Replace the generated key with your own, e.g. one your fleet already trusts. Export it with{' '}
            <Code>gpg --armor --export-secret-keys KEYID</Code>. The key is stored encrypted and never shown again.
          </Text>
          <Textarea
            label="ASCII-armored private key"
            placeholder={'-----BEGIN PGP PRIVATE KEY BLOCK-----\n…\n-----END PGP PRIVATE KEY BLOCK-----'}
            autosize
            minRows={6}
            maxRows={14}
            value={privateKey}
            onChange={(e) => setPrivateKey(e.currentTarget.value)}
            styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)', fontSize: 12 } }}
            error={privateKey && !looksArmored ? 'Expected a "BEGIN PGP PRIVATE KEY BLOCK" armored key' : null}
            required
            data-autofocus
          />
          <PasswordInput
            label="Passphrase"
            description="Only if the key is protected"
            value={passphrase}
            onChange={(e) => setPassphrase(e.currentTarget.value)}
            autoComplete="off"
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!looksArmored} loading={imp.isPending} leftSection={<IconFileImport size={16} />}>
              Import key
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

/** Shows the result of a cleanup run or preview. */
export function CleanupResultView({ result }: { result: CleanupRunResult }) {
  return (
    <Stack gap="sm">
      <SimpleGrid cols={3}>
        <Paper p="sm">
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            Components
          </Text>
          <Text fw={650} size="lg">
            {formatNumber(result.components.length)}
          </Text>
        </Paper>
        <Paper p="sm">
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            Assets
          </Text>
          <Text fw={650} size="lg">
            {formatNumber(result.assets)}
          </Text>
        </Paper>
        <Paper p="sm">
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            {result.dryRun ? 'Would free' : 'Freed'}
          </Text>
          <Text fw={650} size="lg">
            {formatBytes(result.bytes)}
          </Text>
        </Paper>
      </SimpleGrid>
      {result.components.length === 0 ? (
        <Alert variant="light" color="teal" icon={<IconCheck size={18} />}>
          {result.dryRun ? 'Nothing would be deleted.' : 'Nothing was deleted.'}
        </Alert>
      ) : (
        <Paper p={0}>
          <ScrollArea.Autosize mah={320}>
            <Table stickyHeader verticalSpacing={6}>
              <Table.Thead>
                <Table.Tr>
                  {result.repositories.length > 1 && <Table.Th>Repository</Table.Th>}
                  <Table.Th>Component</Table.Th>
                  <Table.Th>Version</Table.Th>
                  <Table.Th>Updated</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {result.components.map((c) => (
                  <Table.Tr key={c.id}>
                    {result.repositories.length > 1 && (
                      <Table.Td>
                        <Text size="sm">{c.repository}</Text>
                      </Table.Td>
                    )}
                    <Table.Td>
                      {result.dryRun ? (
                        <Anchor component={Link} to={`/components/${c.id}`} size="sm">
                          {c.name}
                        </Anchor>
                      ) : (
                        <Text size="sm">{c.name}</Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace">
                        {c.version || '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed" title={formatDate(c.updatedAt)}>
                        {formatRelative(c.updatedAt)}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea.Autosize>
        </Paper>
      )}
    </Stack>
  );
}

/** "Run cleanup now": a dry run first, then the real deletion. */
export function RunCleanupModal({ repository, onClose }: { repository: Repository; onClose: () => void }) {
  const name = repository.name;
  const qc = useQueryClient();
  const policies = repository.cleanup?.policies ?? [];
  const [policy, setPolicy] = useState<string | null>(null);
  const [preview, setPreview] = useState<CleanupRunResult | null>(null);
  const [done, setDone] = useState<CleanupRunResult | null>(null);

  const run = useMutation({
    mutationFn: (dryRun: boolean) =>
      unwrap(
        api.POST('/repositories/{name}/cleanup', {
          params: { path: { name }, query: { dryRun, policy: policy ?? undefined } },
        }),
      ),
    onSuccess: (res) => {
      if (res.dryRun) {
        setPreview(res);
      } else {
        setDone(res);
        qc.invalidateQueries({ queryKey: qk.repository(name) });
        qc.invalidateQueries({ queryKey: ['components'] });
        qc.invalidateQueries({ queryKey: ['browse', name] });
        notifySuccess(`Deleted ${res.components.length} component(s), ${formatBytes(res.bytes)}`, 'Cleanup finished');
      }
    },
  });
  const unavailable = run.error && isNotImplemented(run.error);

  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>Run cleanup on {name}</Text>} size="xl" centered>
      <Stack>
        <Text size="sm" c="dimmed">
          Cleanup normally runs on a schedule. Preview what the policies select, then delete. Components deleted this way
          cannot be restored.
        </Text>
        <Select
          label="Policies"
          data={[{ value: '', label: `All policies (${policies.join(', ')})` }, ...policies.map((p) => ({ value: p, label: p }))]}
          value={policy ?? ''}
          onChange={(v) => {
            setPolicy(v || null);
            setPreview(null);
            setDone(null);
          }}
          allowDeselect={false}
          maw={420}
        />
        {unavailable && (
          <Alert color="gray" variant="light" icon={<IconInfoCircle size={18} />} title="Not available yet">
            Cleanup isn't available on this server yet.
          </Alert>
        )}
        {done ? <CleanupResultView result={done} /> : preview && <CleanupResultView result={preview} />}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {done ? 'Close' : 'Cancel'}
          </Button>
          {!done && (
            <Button variant="light" loading={run.isPending && run.variables === true} onClick={() => run.mutate(true)}>
              {preview ? 'Preview again' : 'Preview (dry run)'}
            </Button>
          )}
          {!done && (
            <Tooltip label="Run a preview first" disabled={!!preview}>
              <Button
                color="red"
                leftSection={<IconEraser size={16} />}
                disabled={!preview || preview.components.length === 0}
                loading={run.isPending && run.variables === false}
                onClick={() => run.mutate(false)}
              >
                Delete {preview ? formatNumber(preview.components.length) : ''} component(s)
              </Button>
            </Tooltip>
          )}
        </Group>
      </Stack>
    </Modal>
  );
}
