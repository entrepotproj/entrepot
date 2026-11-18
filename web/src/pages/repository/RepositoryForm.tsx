import {
  ActionIcon,
  Alert,
  Button,
  Divider,
  Group,
  NumberInput,
  Paper,
  PasswordInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  Textarea,
  TextInput,
  Title,
  Tooltip,
} from '@mantine/core';
import { IconArrowDown, IconArrowUp, IconInfoCircle, IconPlus, IconX } from '@tabler/icons-react';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import type { Repository, RepositoryInput, RepositoryKind } from '../../api/client';
import { useBlobStores, useRepositories, useSystemInfo } from '../../api/queries';
import { formatLabel, KindBadge, kindHelp } from '../../components/badges';
import {
  AptDistributionsEditor,
  CleanupFields,
  DEFAULT_APT_DIST,
  PreferHostedField,
  RoutingRuleField,
  ScanFields,
  type AptDist,
  type ScanForm,
} from './FormSections';

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;

export const DEFAULT_REMOTES: Record<string, string> = {
  raw: '',
  pypi: 'https://pypi.org',
  npm: 'https://registry.npmjs.org',
  docker: 'https://registry-1.docker.io',
  apt: 'http://deb.debian.org/debian',
  yum: 'https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os',
  helm: 'https://prometheus-community.github.io/helm-charts',
};

/** Formats whose groups can prefer hosted members (dependency-confusion protection). */
const PREFER_HOSTED_FORMATS = ['npm', 'pypi', 'helm'];

type Format = RepositoryInput['format'];

type State = {
  name: string;
  format: string;
  kind: RepositoryKind;
  blobStore: string;
  description: string;
  online: boolean;
  anonymousRead: boolean;
  allowRedeploy: boolean;
  remoteUrl: string;
  username: string;
  password: string;
  metadataTtl: number | '';
  contentTtl: number | '';
  negativeTtl: number | '';
  members: string[];
  preferHosted: boolean;
  routingRule: string;
  aptDistributions: AptDist[];
  repodataDepth: number | '';
  scan: ScanForm;
  cleanupPolicies: string[];
};

function initialState(r?: Repository): State {
  return {
    name: r?.name ?? '',
    format: r?.format ?? '',
    kind: r?.kind ?? 'hosted',
    blobStore: r?.blobStore ?? '',
    description: r?.description ?? '',
    online: r?.online ?? true,
    anonymousRead: r?.anonymousRead ?? false,
    allowRedeploy: r?.hosted?.allowRedeploy ?? false,
    remoteUrl: r?.proxy?.remoteUrl ?? '',
    username: r?.proxy?.username ?? '',
    password: '',
    metadataTtl: r?.proxy?.metadataTtlSeconds ?? '',
    contentTtl: r?.proxy?.contentTtlSeconds ?? '',
    negativeTtl: r?.proxy?.negativeCacheTtlSeconds ?? '',
    members: r?.group?.members ?? [],
    preferHosted: r?.group?.preferHosted ?? true,
    routingRule: r?.proxy?.routingRule ?? '',
    aptDistributions: r
      ? (r.hosted?.apt?.distributions ?? []).map((d) => ({
          name: d.name,
          components: d.components ?? [],
          architectures: d.architectures ?? [],
          origin: d.origin ?? '',
          label: d.label ?? '',
        }))
      : [{ ...DEFAULT_APT_DIST }],
    repodataDepth: r?.hosted?.yum?.repodataDepth ?? 0,
    scan: {
      scanners: r?.scan?.scanners ?? [],
      mode: r?.scan?.mode ?? 'warn',
      severityThreshold: r?.scan?.severityThreshold ?? 'high',
      onUpload: r?.scan?.onUpload ?? true,
      onProxyFetch: r?.scan?.onProxyFetch ?? true,
      blockUntilScanned: r?.scan?.blockUntilScanned ?? false,
      distro: r?.scan?.distro ?? '',
    },
    cleanupPolicies: r?.cleanup?.policies ?? [],
  };
}

function toInput(s: State, original?: Repository): RepositoryInput {
  const num = (v: number | '') => (v === '' ? undefined : v);
  const input: RepositoryInput = {
    name: s.name.trim(),
    format: s.format as Format,
    kind: s.kind,
    blobStore: s.blobStore,
    description: s.description,
    online: s.online,
    anonymousRead: s.anonymousRead,
  };
  if (s.kind === 'hosted') {
    input.hosted = { allowRedeploy: s.allowRedeploy };
    if (s.format === 'apt') {
      input.hosted.apt = {
        distributions: s.aptDistributions
          .filter((d) => d.name.trim())
          .map((d) => ({
            name: d.name.trim(),
            components: d.components,
            architectures: d.architectures,
            origin: d.origin.trim() || undefined,
            label: d.label.trim() || undefined,
          })),
      };
    }
    if (s.format === 'yum') input.hosted.yum = { repodataDepth: s.repodataDepth === '' ? 0 : s.repodataDepth };
  }
  if (s.kind === 'proxy') {
    input.proxy = {
      remoteUrl: s.remoteUrl.trim(),
      username: s.username || undefined,
      password: s.password || undefined,
      metadataTtlSeconds: num(s.metadataTtl),
      contentTtlSeconds: num(s.contentTtl),
      negativeCacheTtlSeconds: num(s.negativeTtl),
      routingRule: s.routingRule || undefined,
    };
  }
  if (s.kind === 'group') {
    input.group = { members: s.members };
    if (PREFER_HOSTED_FORMATS.includes(s.format)) input.group.preferHosted = s.preferHosted;
  }
  // Only send scan/cleanup settings when they are in use, so servers without
  // these features keep accepting the request.
  if (s.scan.scanners.length > 0 || original?.scan) {
    input.scan = {
      scanners: s.scan.scanners,
      mode: s.scan.mode,
      severityThreshold: s.scan.severityThreshold as NonNullable<RepositoryInput['scan']>['severityThreshold'],
      onUpload: s.scan.onUpload,
      onProxyFetch: s.scan.onProxyFetch,
      blockUntilScanned: s.scan.blockUntilScanned,
      distro: s.scan.distro || undefined,
    };
  }
  if (s.cleanupPolicies.length > 0 || original?.cleanup) input.cleanup = { policies: s.cleanupPolicies };
  return input;
}

function Section({ title, description, children }: { title: string; description?: ReactNode; children: ReactNode }) {
  return (
    <Paper p="lg">
      <Title order={5} mb={4}>
        {title}
      </Title>
      {description && (
        <Text size="sm" c="dimmed" mb="md">
          {description}
        </Text>
      )}
      <Stack gap="md" mt={description ? 0 : 'md'}>
        {children}
      </Stack>
    </Paper>
  );
}

export function RepositoryForm({
  repository,
  onSubmit,
  submitting,
  submitLabel,
  extraActions,
}: {
  repository?: Repository;
  onSubmit: (input: RepositoryInput) => void;
  submitting?: boolean;
  submitLabel: string;
  extraActions?: ReactNode;
}) {
  const editing = !!repository;
  const [s, setS] = useState<State>(() => initialState(repository));
  const [touched, setTouched] = useState(false);
  const { data: info } = useSystemInfo();
  const blobStores = useBlobStores(!editing);
  const { data: repos } = useRepositories();

  // Preselect the blob store when there is only one (or one named "default").
  useEffect(() => {
    if (editing || s.blobStore || !blobStores.data?.length) return;
    const def = blobStores.data.find((b) => b.name === 'default') ?? (blobStores.data.length === 1 ? blobStores.data[0] : undefined);
    if (def) setS((p) => ({ ...p, blobStore: def.name }));
  }, [editing, blobStores.data, s.blobStore]);

  const set = <K extends keyof State>(k: K, v: State[K]) => setS((p) => ({ ...p, [k]: v }));

  const formatInfo = info?.formats.find((f) => f.name === s.format);
  const kinds = formatInfo?.kinds ?? (['hosted', 'proxy', 'group'] as RepositoryKind[]);

  const memberOptions = useMemo(
    () =>
      (repos ?? [])
        .filter((r) => r.format === s.format && r.name !== s.name && !s.members.includes(r.name))
        .map((r) => ({ value: r.name, label: `${r.name} (${r.kind})` })),
    [repos, s.format, s.name, s.members],
  );

  const changeFormat = (f: string | null) => {
    if (!f) return;
    setS((p) => {
      const fi = info?.formats.find((x) => x.name === f);
      const kind = fi && !fi.kinds.includes(p.kind) ? fi.kinds[0] : p.kind;
      const wasDefault = !p.remoteUrl || Object.values(DEFAULT_REMOTES).includes(p.remoteUrl);
      return {
        ...p,
        format: f,
        kind,
        remoteUrl: wasDefault ? (DEFAULT_REMOTES[f] ?? '') : p.remoteUrl,
        members: p.format === f ? p.members : [],
        // Docker: allowRedeploy means "allow moving tags" and defaults to on.
        allowRedeploy: editing ? p.allowRedeploy : f === 'docker',
      };
    });
  };

  const errors = {
    name: !NAME_RE.test(s.name) ? "Lowercase letters, digits, '.', '_' and '-' (max 63)" : null,
    format: !s.format ? 'Choose a format' : null,
    blobStore: !s.blobStore ? 'Choose a blob store' : null,
    remoteUrl: s.kind === 'proxy' && !/^https?:\/\/.+/.test(s.remoteUrl.trim()) ? 'An http(s) URL is required' : null,
    members: s.kind === 'group' && s.members.length === 0 ? 'Add at least one member' : null,
    apt:
      s.kind === 'hosted' &&
      s.format === 'apt' &&
      (s.aptDistributions.some((d) => !d.name.trim()) ||
        new Set(s.aptDistributions.map((d) => d.name.trim())).size !== s.aptDistributions.length)
        ? 'Check the distributions'
        : null,
  };
  const valid = Object.values(errors).every((e) => !e);
  const err = (k: keyof typeof errors) => (touched ? errors[k] : null);

  const move = (i: number, d: number) =>
    setS((p) => {
      const m = [...p.members];
      const j = i + d;
      if (j < 0 || j >= m.length) return p;
      [m[i], m[j]] = [m[j], m[i]];
      return { ...p, members: m };
    });

  const formatOptions = (info?.formats ?? []).map((f) => ({ value: f.name, label: formatLabel(f.name) }));
  if (editing && !formatOptions.some((o) => o.value === s.format)) {
    formatOptions.push({ value: s.format, label: formatLabel(s.format) });
  }
  const blobOptions = editing
    ? [{ value: s.blobStore, label: s.blobStore }]
    : (blobStores.data ?? []).map((b) => ({ value: b.name, label: `${b.name} (${b.type})` }));

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setTouched(true);
        if (valid) onSubmit(toInput(s, repository));
      }}
    >
      <Stack gap="md">
        <Section title="General">
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <TextInput
              label="Name"
              description={editing ? undefined : 'Used in client URLs; cannot be changed later.'}
              placeholder="npm-internal"
              value={s.name}
              onChange={(e) => set('name', e.currentTarget.value.toLowerCase())}
              disabled={editing}
              error={err('name')}
              required
              data-autofocus
            />
            <Select
              label="Format"
              description={editing ? undefined : 'The package ecosystem clients speak.'}
              placeholder="Select a format"
              data={formatOptions}
              value={s.format || null}
              onChange={changeFormat}
              disabled={editing}
              error={err('format')}
              required
              allowDeselect={false}
            />
            <Select
              label="Kind"
              description={editing ? undefined : kindHelp(s.kind)}
              data={kinds.map((k) => ({ value: k, label: k[0].toUpperCase() + k.slice(1) }))}
              value={s.kind}
              onChange={(v) => v && set('kind', v as RepositoryKind)}
              disabled={editing || !s.format}
              required
              allowDeselect={false}
            />

            <Select
              label="Blob store"
              description={editing ? undefined : 'Where artifact content is stored; cannot be changed later.'}
              placeholder={blobStores.isPending && !editing ? 'Loading…' : 'Select a blob store'}
              data={blobOptions}
              value={s.blobStore || null}
              onChange={(v) => set('blobStore', v ?? '')}
              disabled={editing}
              error={err('blobStore') ?? (blobStores.error ? 'Could not load blob stores' : null)}
              required
              allowDeselect={false}
            />          </SimpleGrid>
          <Textarea
            label="Description"
            placeholder="What is this repository for?"
            autosize
            minRows={2}
            value={s.description}
            onChange={(e) => set('description', e.currentTarget.value)}
          />
          <Group gap="xl">
            <Switch
              label="Online"
              description="Offline repositories reject client requests"
              checked={s.online}
              onChange={(e) => set('online', e.currentTarget.checked)}
            />
            <Switch
              label="Anonymous read"
              description="Anyone can download without signing in"
              checked={s.anonymousRead}
              onChange={(e) => set('anonymousRead', e.currentTarget.checked)}
            />
          </Group>
        </Section>

        {s.kind === 'hosted' && (
          <Section title="Hosted" description="Artifacts are published to this repository by clients or uploads.">
            <Switch
              label={s.format === 'docker' ? 'Allow overwriting tags (e.g. latest)' : 'Allow redeploy'}
              description={
                s.format === 'docker'
                  ? 'Allow pushing a tag that already points to another image. Turn off for immutable tags.'
                  : 'Allow overwriting existing artifacts and versions. Leave off for immutable releases.'
              }
              checked={s.allowRedeploy}
              onChange={(e) => set('allowRedeploy', e.currentTarget.checked)}
            />
            {s.format === 'yum' && (
              <NumberInput
                label="Repodata depth"
                description={
                  <>
                    Directory depth at which <code>repodata/</code> is generated. 0 = repository root; 2 = one repodata per
                    e.g. <code>el9/x86_64/</code> directory.
                  </>
                }
                min={0}
                max={5}
                maw={360}
                value={s.repodataDepth}
                onChange={(v) => set('repodataDepth', typeof v === 'number' ? v : '')}
              />
            )}
          </Section>
        )}

        {s.kind === 'hosted' && s.format === 'apt' && (
          <Section
            title="Apt distributions"
            description="Each distribution (suite) gets signed Release/InRelease files listing its components and architectures. Packages are uploaded into a distribution and component."
          >
            <AptDistributionsEditor value={s.aptDistributions} onChange={(v) => set('aptDistributions', v)} />
          </Section>
        )}

        {s.kind === 'proxy' && (
          <Section title="Proxy" description="Requests are served from cache, falling back to the remote registry.">
            <TextInput
              label="Remote URL"
              placeholder={DEFAULT_REMOTES[s.format] || 'https://example.com/files'}
              value={s.remoteUrl}
              onChange={(e) => set('remoteUrl', e.currentTarget.value)}
              error={err('remoteUrl')}
              required
            />
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label="Username"
                description="Optional credentials for the remote"
                value={s.username}
                onChange={(e) => set('username', e.currentTarget.value)}
                autoComplete="off"
              />
              <PasswordInput
                label="Password"
                description={editing ? 'Leave empty to keep the stored password' : 'Optional'}
                value={s.password}
                onChange={(e) => set('password', e.currentTarget.value)}
                autoComplete="new-password"
              />
            </SimpleGrid>
            <Divider label="Caching" labelPosition="left" />
            <SimpleGrid cols={{ base: 1, sm: 3 }}>
              <NumberInput
                label="Metadata TTL (seconds)"
                description="Index/metadata freshness. Default 3600."
                placeholder="3600"
                min={0}
                value={s.metadataTtl}
                onChange={(v) => set('metadataTtl', typeof v === 'number' ? v : '')}
              />
              <NumberInput
                label="Content TTL (seconds)"
                description="0 = cached artifacts never expire (default)."
                placeholder="0"
                min={0}
                value={s.contentTtl}
                onChange={(v) => set('contentTtl', typeof v === 'number' ? v : '')}
              />
              <NumberInput
                label="Negative cache TTL (seconds)"
                description="Remember misses. Default 300; -1 disables."
                placeholder="300"
                min={-1}
                value={s.negativeTtl}
                onChange={(v) => set('negativeTtl', typeof v === 'number' ? v : '')}
              />
            </SimpleGrid>
            <Divider label="Routing" labelPosition="left" />
            <RoutingRuleField value={s.routingRule} onChange={(v) => set('routingRule', v)} />
          </Section>
        )}

        {s.kind === 'group' && (
          <Section
            title="Group members"
            description="Members are searched in order; the first repository that has an artifact wins. Only repositories of the same format can be members."
          >
            <Select
              placeholder={s.format ? 'Add a member repository…' : 'Choose a format first'}
              data={memberOptions}
              value={null}
              onChange={(v) => v && set('members', [...s.members, v])}
              searchable
              disabled={!s.format}
              leftSection={<IconPlus size={16} />}
              nothingFoundMessage={`No other ${formatLabel(s.format)} repositories`}
              error={err('members')}
            />
            {s.members.length > 0 && (
              <Stack gap={6}>
                {s.members.map((m, i) => (
                  <Paper key={m} p="xs" px="sm">
                    <Group justify="space-between" wrap="nowrap">
                      <Group gap="sm">
                        <Text size="sm" c="dimmed" w={20} ta="right">
                          {i + 1}.
                        </Text>
                        <Text size="sm" fw={500}>
                          {m}
                        </Text>
                        {(() => {
                          const mr = repos?.find((r) => r.name === m);
                          return mr ? <KindBadge kind={mr.kind} size="xs" /> : null;
                        })()}
                      </Group>
                      <Group gap={2}>
                        <Tooltip label="Move up">
                          <ActionIcon variant="subtle" color="gray" disabled={i === 0} onClick={() => move(i, -1)}>
                            <IconArrowUp size={16} />
                          </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Move down">
                          <ActionIcon
                            variant="subtle"
                            color="gray"
                            disabled={i === s.members.length - 1}
                            onClick={() => move(i, 1)}
                          >
                            <IconArrowDown size={16} />
                          </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Remove">
                          <ActionIcon
                            variant="subtle"
                            color="red"
                            onClick={() => set('members', s.members.filter((x) => x !== m))}
                          >
                            <IconX size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Group>
                    </Group>
                  </Paper>
                ))}
              </Stack>
            )}
            {PREFER_HOSTED_FORMATS.includes(s.format) && (
              <PreferHostedField checked={s.preferHosted} onChange={(v) => set('preferHosted', v)} />
            )}
          </Section>
        )}

        {s.format && s.kind !== 'group' && (
          <Section
            title="Vulnerability scanning"
            description="Scan components for known vulnerabilities, and optionally quarantine vulnerable ones."
          >
            <ScanFields
              value={s.scan}
              onChange={(patch) => setS((p) => ({ ...p, scan: { ...p.scan, ...patch } }))}
              format={s.format}
              kind={s.kind}
            />
          </Section>
        )}

        {s.format && s.kind !== 'group' && (
          <Section title="Cleanup" description="Delete old or unused components automatically.">
            <CleanupFields value={s.cleanupPolicies} onChange={(v) => set('cleanupPolicies', v)} format={s.format} />
          </Section>
        )}

        {touched && !valid && (
          <Alert color="orange" variant="light" icon={<IconInfoCircle size={18} />}>
            Please fix the highlighted fields.
          </Alert>
        )}

        <Group justify="space-between">
          <div>{extraActions}</div>
          <Button type="submit" loading={submitting}>
            {submitLabel}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
