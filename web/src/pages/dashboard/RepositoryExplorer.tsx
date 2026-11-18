import {
  ActionIcon,
  Anchor,
  Badge,
  Button,
  Card,
  Chip,
  Code,
  CopyButton,
  Group,
  Paper,
  ScrollArea,
  SimpleGrid,
  Skeleton,
  Stack,
  Text,
  TextInput,
  Title,
  Tooltip,
} from '@mantine/core';
import {
  IconCheck,
  IconCopy,
  IconLink,
  IconLock,
  IconPackages,
  IconPlus,
  IconSearch,
  IconTerminal2,
  IconWorld,
  IconX,
} from '@tabler/icons-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import type { Repository } from '../../api/client';
import { useRepositories, useSystemInfo } from '../../api/queries';
import { FormatBadge, FormatIcon, formatLabel, KindBadge, OnlineBadge } from '../../components/badges';
import { EmptyState, QueryError } from '../../components/states';
import { formatBytes, formatNumber } from '../../lib/format';
import { readStored, writeStored } from '../../lib/storage';
import { quickCommand } from '../repository/ClientSetup';

const FORMAT_KEY = 'entrepot-explorer-format';
const kindOrder: Record<string, number> = { group: 0, hosted: 1, proxy: 2 };

function CopyAction({ value, label }: { value: string; label: string }) {
  return (
    <CopyButton value={value} timeout={1500}>
      {({ copied, copy }) => (
        <Tooltip label={copied ? 'Copied' : label} withArrow>
          <ActionIcon variant="subtle" color={copied ? 'teal' : 'gray'} size="sm" onClick={copy} aria-label={label}>
            {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
          </ActionIcon>
        </Tooltip>
      )}
    </CopyButton>
  );
}

function RepositoryCard({ r, baseUrl }: { r: Repository; baseUrl: string }) {
  const cmd = quickCommand(r, baseUrl);
  const canWrite = r.permissions.includes('write') && r.kind === 'hosted';
  return (
    <Card p="md" h="100%" style={{ display: 'flex', flexDirection: 'column' }}>
      <Group gap="sm" wrap="nowrap" align="flex-start">
        <FormatIcon format={r.format} size={22} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <Group gap={6} wrap="nowrap">
            <Anchor component={Link} to={`/repositories/${r.name}`} fw={650} size="sm" truncate="end">
              {r.name}
            </Anchor>
            {r.anonymousRead ? (
              <Tooltip label="Public: readable without signing in" withArrow>
                <IconWorld size={14} color="var(--mantine-color-dimmed)" style={{ flexShrink: 0 }} />
              </Tooltip>
            ) : (
              <Tooltip label="Private: requires authentication" withArrow>
                <IconLock size={14} color="var(--mantine-color-dimmed)" style={{ flexShrink: 0 }} />
              </Tooltip>
            )}
          </Group>
          <Group gap={4} mt={6}>
            <FormatBadge format={r.format} size="sm" />
            <KindBadge kind={r.kind} size="sm" />
            {canWrite && (
              <Badge size="sm" variant="light" color="teal" radius="sm" tt="none">
                can publish
              </Badge>
            )}
            {!r.online && <OnlineBadge online={false} />}
          </Group>
        </div>
      </Group>

      <Text size="xs" c={r.description ? undefined : 'dimmed'} mt="sm" lineClamp={2} mih={34}>
        {r.description ||
          (r.kind === 'proxy'
            ? `Caches ${r.proxy?.remoteUrl ?? 'a remote registry'}`
            : r.kind === 'group'
              ? `Groups ${r.group?.members.join(', ') ?? 'repositories'}`
              : 'No description')}
      </Text>

      {r.stats && (
        <Text size="xs" c="dimmed" mt={6}>
          {formatNumber(r.stats.components)} component{r.stats.components === 1 ? '' : 's'} · {formatBytes(r.stats.totalBytes)}
        </Text>
      )}

      <Paper withBorder={false} bg="var(--mantine-color-default-hover)" px={8} py={6} mt="sm" radius="sm">
        <Group gap={6} wrap="nowrap" justify="space-between">
          <Tooltip label={cmd.title} withArrow openDelay={400}>
            <IconTerminal2 size={14} color="var(--mantine-color-dimmed)" style={{ flexShrink: 0 }} />
          </Tooltip>
          <Code
            fz={11}
            bg="transparent"
            p={0}
            style={{ flex: 1, minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}
            title={cmd.code}
          >
            {cmd.code}
          </Code>
          <CopyAction value={cmd.code} label={`Copy: ${cmd.title.toLowerCase()}`} />
        </Group>
      </Paper>

      <Group justify="space-between" mt="sm" pt={4} style={{ marginTop: 'auto' }} wrap="nowrap">
        <CopyButton value={r.url} timeout={1500}>
          {({ copied, copy }) => (
            <Button
              size="compact-xs"
              variant="subtle"
              color={copied ? 'teal' : 'gray'}
              leftSection={copied ? <IconCheck size={13} /> : <IconLink size={13} />}
              onClick={copy}
            >
              {copied ? 'Copied' : 'Copy URL'}
            </Button>
          )}
        </CopyButton>
        <Button component={Link} to={`/repositories/${r.name}`} size="compact-xs" variant="light">
          Set up
        </Button>
      </Group>
    </Card>
  );
}

/** Card grid of the repositories the caller can read, filterable by format and searchable. */
export function RepositoryExplorer({ anonymous, admin }: { anonymous: boolean; admin: boolean }) {
  const { data: repos, isPending, error, refetch } = useRepositories();
  const { data: info } = useSystemInfo();
  const baseUrl = (info?.baseUrl || window.location.origin).replace(/\/+$/, '');
  const [q, setQ] = useState('');
  const [format, setFormatState] = useState(() => readStored(FORMAT_KEY) ?? 'all');
  const setFormat = (f: string) => {
    setFormatState(f);
    writeStored(FORMAT_KEY, f);
  };

  const counts = useMemo(() => {
    const m = new Map<string, number>();
    repos?.forEach((r) => m.set(r.format, (m.get(r.format) ?? 0) + 1));
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [repos]);
  const activeFormat = format !== 'all' && counts.some(([f]) => f === format) ? format : 'all';

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (repos ?? [])
      .filter((r) => activeFormat === 'all' || r.format === activeFormat)
      .filter(
        (r) =>
          !needle ||
          r.name.toLowerCase().includes(needle) ||
          r.description.toLowerCase().includes(needle) ||
          r.format.includes(needle) ||
          (r.proxy?.remoteUrl ?? '').toLowerCase().includes(needle),
      )
      .sort((a, b) => (kindOrder[a.kind] ?? 9) - (kindOrder[b.kind] ?? 9) || a.name.localeCompare(b.name));
  }, [repos, activeFormat, q]);

  // With "All formats", no search and enough repositories to make it worth it, group the cards by format.
  const groups = useMemo(() => {
    if (activeFormat !== 'all' || q.trim() || filtered.length < 7 || counts.length < 2) return [{ format: '', items: filtered }];
    return counts.map(([f]) => ({ format: f, items: filtered.filter((r) => r.format === f) })).filter((g) => g.items.length);
  }, [filtered, counts, activeFormat, q]);

  return (
    <section id="repositories" aria-labelledby="explorer-title">
      <Group justify="space-between" align="flex-end" mb="sm" wrap="wrap" gap="sm">
        <div>
          <Title order={3} id="explorer-title">
            {anonymous ? 'Public repositories' : 'Your repositories'}
          </Title>
          <Text size="sm" c="dimmed">
            {anonymous
              ? 'Repositories anyone can read. Sign in to see the rest.'
              : 'Everything you can read. Copy a URL or a command, or open a repository for full client setup.'}
          </Text>
        </div>
        <Group gap="xs">
          <TextInput
            size="xs"
            w={240}
            placeholder="Search repositories"
            leftSection={<IconSearch size={14} />}
            rightSection={
              q ? (
                <ActionIcon size="xs" variant="subtle" color="gray" onClick={() => setQ('')} aria-label="Clear search">
                  <IconX size={12} />
                </ActionIcon>
              ) : null
            }
            value={q}
            onChange={(e) => setQ(e.currentTarget.value)}
            aria-label="Search repositories"
          />
          {admin && (
            <Button component={Link} to="/repositories/new" size="xs" leftSection={<IconPlus size={14} />}>
              New
            </Button>
          )}
        </Group>
      </Group>

      {counts.length > 1 && (
        <ScrollArea type="never" mb="md">
          <Chip.Group value={activeFormat} onChange={(v) => setFormat(v as string)}>
            <Group gap={6} wrap="nowrap">
              <Chip value="all" size="xs" radius="sm" variant="light">
                All · {repos?.length ?? 0}
              </Chip>
              {counts.map(([f, n]) => (
                <Chip key={f} value={f} size="xs" radius="sm" variant="light">
                  {formatLabel(f)} · {n}
                </Chip>
              ))}
            </Group>
          </Chip.Group>
        </ScrollArea>
      )}

      {error ? (
        <QueryError error={error} retry={refetch} />
      ) : isPending ? (
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} spacing="md">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} h={190} radius="md" />
          ))}
        </SimpleGrid>
      ) : filtered.length === 0 ? (
        <Paper>
          <EmptyState
            icon={<IconPackages size={28} stroke={1.5} />}
            title={repos.length > 0 ? 'No matching repositories' : 'No repositories yet'}
            description={
              repos.length > 0
                ? 'Try a different search or format.'
                : anonymous
                  ? 'No repositories are readable anonymously. Sign in to see more.'
                  : admin
                    ? 'Create a hosted repository to publish packages, or a proxy to cache a public registry.'
                    : 'You do not have access to any repository yet. Ask an administrator for a role binding.'
            }
            action={
              anonymous ? (
                <Button component={Link} to="/login?return=/" variant="light">
                  Sign in
                </Button>
              ) : (
                admin &&
                repos.length === 0 && (
                  <Button component={Link} to="/repositories/new" leftSection={<IconPlus size={16} />}>
                    Create repository
                  </Button>
                )
              )
            }
          />
        </Paper>
      ) : (
        <Stack gap="lg">
          {groups.map((g) => (
            <div key={g.format || 'all'}>
              {g.format && groups.length > 1 && (
                <Group gap={8} mb={8}>
                  <FormatIcon format={g.format} size={16} />
                  <Text size="sm" fw={650}>
                    {formatLabel(g.format)}
                  </Text>
                  <Text size="xs" c="dimmed">
                    {g.items.length}
                  </Text>
                </Group>
              )}
              <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} spacing="md">
                {g.items.map((r) => (
                  <RepositoryCard key={r.name} r={r} baseUrl={baseUrl} />
                ))}
              </SimpleGrid>
            </div>
          ))}
        </Stack>
      )}
    </section>
  );
}
