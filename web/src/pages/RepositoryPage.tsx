import { Badge, Divider, Grid, Group, Paper, SimpleGrid, Skeleton, Stack, Tabs, Text, ThemeIcon, Tooltip } from '@mantine/core';
import {
  IconFolder,
  IconLock,
  IconPackage,
  IconSettings,
  IconStack2,
  IconUpload,
  IconWorld,
} from '@tabler/icons-react';
import { useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useRepository } from '../api/queries';
import { FormatBadge, FormatIcon, KindBadge, OnlineBadge } from '../components/badges';
import { CopyText } from '../components/CodeBlock';
import { PageHeader } from '../components/PageHeader';
import { EmptyState, QueryError } from '../components/states';
import { formatBytes, formatDuration, formatNumber } from '../lib/format';
import { BrowseTab } from './repository/BrowseTab';
import { ClientSetup } from './repository/ClientSetup';
import { ComponentsTab } from './repository/ComponentsTab';
import { SettingsTab } from './repository/SettingsTab';
import { UploadTab } from './repository/UploadTab';
import { RunCleanupModal, settingsRows, SigningKeyPanel } from './repository/RepositoryExtras';
import { ApiError } from '../api/client';

const UPLOAD_FORMATS = ['raw', 'pypi', 'npm', 'apt', 'yum', 'helm'];

function Stat({ label, value, icon }: { label: string; value: ReactNode; icon: ReactNode }) {
  return (
    <Group gap="sm" wrap="nowrap">
      <ThemeIcon variant="light" size={34} radius="md" visibleFrom="sm">
        {icon}
      </ThemeIcon>
      <div style={{ minWidth: 0 }}>
        <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: 0.3 }}>
          {label}
        </Text>
        <Text fw={650} size="lg" lh={1.2} style={{ whiteSpace: 'nowrap' }}>
          {value}
        </Text>
      </div>
    </Group>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Group justify="space-between" wrap="nowrap" align="flex-start" gap="md">
      <Text size="sm" c="dimmed" style={{ whiteSpace: 'nowrap' }}>
        {label}
      </Text>
      <div style={{ minWidth: 0, flex: 1, display: 'flex', justifyContent: 'flex-end', overflow: 'hidden' }}>{children}</div>
    </Group>
  );
}

export function RepositoryPage() {
  const { name = '', tab = 'browse' } = useParams();
  const navigate = useNavigate();
  const { data: r, isPending, error, refetch } = useRepository(name);
  const [cleanupOpen, setCleanupOpen] = useState(false);

  if (error) {
    if (error instanceof ApiError && error.notFound) {
      return (
        <EmptyState
          title="Repository not found"
          description={`There is no repository named ${name}, or you are not allowed to see it.`}
        />
      );
    }
    return <QueryError error={error} retry={refetch} />;
  }
  if (isPending) {
    return (
      <Stack>
        <Skeleton height={40} width={320} />
        <SimpleGrid cols={3}>
          <Skeleton height={72} />
          <Skeleton height={72} />
          <Skeleton height={72} />
        </SimpleGrid>
        <Skeleton height={300} />
      </Stack>
    );
  }

  const canUpload = r.permissions.includes('write') && r.kind === 'hosted' && UPLOAD_FORMATS.includes(r.format);
  const canAdmin = r.permissions.includes('admin');
  const signed = r.kind === 'hosted' && (r.format === 'apt' || r.format === 'yum');
  const tabs = ['browse', 'components', ...(canUpload ? ['upload'] : []), ...(canAdmin ? ['settings'] : [])];
  const active = tabs.includes(tab) ? tab : 'browse';

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Repositories', to: '/repositories' }, { label: r.name }]}
        icon={
          <ThemeIcon size={44} radius="md" variant="light">
            <FormatIcon format={r.format} size={26} />
          </ThemeIcon>
        }
        title={r.name}
        description={r.description || undefined}
        actions={
          <Group gap={6}>
            <FormatBadge format={r.format} size="lg" />
            <KindBadge kind={r.kind} size="lg" />
            <OnlineBadge online={r.online} />
            {r.anonymousRead ? (
              <Tooltip label="Anyone can read without signing in">
                <Badge variant="light" color="green" leftSection={<IconWorld size={12} />} tt="none" radius="sm">
                  Public
                </Badge>
              </Tooltip>
            ) : (
              <Tooltip label="Requires authentication">
                <Badge variant="light" color="gray" leftSection={<IconLock size={12} />} tt="none" radius="sm">
                  Private
                </Badge>
              </Tooltip>
            )}
          </Group>
        }
      />

      <Grid gutter="md" mb="lg">
        <Grid.Col span={{ base: 12, lg: 5 }}>
          <Paper p="lg" h="100%">
            <SimpleGrid cols={3} spacing="sm">
              <Stat label="Assets" value={formatNumber(r.stats?.assets)} icon={<IconFolder size={18} />} />
              <Stat label="Components" value={formatNumber(r.stats?.components)} icon={<IconPackage size={18} />} />
              <Stat label="Size" value={formatBytes(r.stats?.totalBytes)} icon={<IconStack2 size={18} />} />
            </SimpleGrid>
            <Divider my="md" />
            <Stack gap={10}>
              <Row label="URL">
                <CopyText value={r.url} maw="100%" />
              </Row>
              <Row label="Blob store">
                <Text size="sm">{r.blobStore}</Text>
              </Row>
              {r.proxy && (
                <>
                  <Row label="Remote">
                    <CopyText value={r.proxy.remoteUrl} maw="100%" />
                  </Row>
                  <Row label="Metadata / content TTL">
                    <Text size="sm">
                      {formatDuration(r.proxy.metadataTtlSeconds ?? 3600)} / {formatDuration(r.proxy.contentTtlSeconds ?? 0)}
                    </Text>
                  </Row>
                </>
              )}
              {r.hosted && (
                <Row label={r.format === 'docker' ? 'Tag overwrites' : 'Redeploy'}>
                  <Text size="sm">{r.hosted.allowRedeploy ? 'Allowed' : 'Disabled (immutable)'}</Text>
                </Row>
              )}
              {r.group && (
                <Row label="Members">
                  <Group gap={4} justify="flex-end">
                    {r.group.members.map((m, i) => (
                      <Badge
                        key={m}
                        component={Link}
                        to={`/repositories/${m}`}
                        variant="default"
                        tt="none"
                        radius="sm"
                        style={{ cursor: 'pointer' }}
                      >
                        {i + 1}. {m}
                      </Badge>
                    ))}
                  </Group>
                </Row>
              )}
              {settingsRows(r, canAdmin, () => setCleanupOpen(true)).map(([label, node]) => (
                <Row key={label} label={label}>
                  {node}
                </Row>
              ))}
              <Row label="Your permissions">
                <Group gap={4} justify="flex-end">
                  {r.permissions.length === 0 && (
                    <Text size="sm" c="dimmed">
                      none
                    </Text>
                  )}
                  {r.permissions.map((p) => (
                    <Badge key={p} size="sm" variant="light" color="gray" radius="sm">
                      {p}
                    </Badge>
                  ))}
                </Group>
              </Row>
            </Stack>
          </Paper>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 7 }}>
          <Stack gap="md" h="100%">
            {signed && <SigningKeyPanel repository={r} />}
            <div style={{ flex: 1 }}>
              <ClientSetup repository={r} />
            </div>
          </Stack>
        </Grid.Col>
      </Grid>
      {cleanupOpen && <RunCleanupModal repository={r} onClose={() => setCleanupOpen(false)} />}

      <Tabs value={active} onChange={(v) => navigate(`/repositories/${r.name}/${v}`)} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="browse" leftSection={<IconFolder size={16} />}>
            Browse
          </Tabs.Tab>
          <Tabs.Tab value="components" leftSection={<IconPackage size={16} />}>
            Components
          </Tabs.Tab>
          {canUpload && (
            <Tabs.Tab value="upload" leftSection={<IconUpload size={16} />}>
              Upload
            </Tabs.Tab>
          )}
          {canAdmin && (
            <Tabs.Tab value="settings" leftSection={<IconSettings size={16} />}>
              Settings
            </Tabs.Tab>
          )}
        </Tabs.List>
        <Tabs.Panel value="browse">
          <BrowseTab repository={r} />
        </Tabs.Panel>
        <Tabs.Panel value="components">
          <ComponentsTab repository={r} />
        </Tabs.Panel>
        {canUpload && (
          <Tabs.Panel value="upload">
            <UploadTab repository={r} />
          </Tabs.Panel>
        )}
        {canAdmin && (
          <Tabs.Panel value="settings">
            <SettingsTab repository={r} />
          </Tabs.Panel>
        )}
      </Tabs>
    </>
  );
}
