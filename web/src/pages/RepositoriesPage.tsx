import {
  Anchor,
  Badge,
  Button,
  Group,
  Paper,
  SegmentedControl,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
  UnstyledButton,
} from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { IconPackages, IconPlus, IconSearch, IconWorld } from '@tabler/icons-react';
import { useMemo, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { useRepositories, useSystemInfo } from '../api/queries';
import { FormatBadge, FormatIcon, formatLabel, KindBadge, OnlineBadge } from '../components/badges';
import { CopyText } from '../components/CodeBlock';
import { PageHeader } from '../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../components/states';
import { useAuth } from '../lib/auth';

export function RepositoriesPage() {
  const { data: repos, isPending, error, refetch } = useRepositories();
  const { data: info } = useSystemInfo();
  const { admin, anonymous } = useAuth();
  const [params, setParams] = useSearchParams();
  const format = params.get('format') ?? 'all';
  const [filter, setFilter] = useState('');
  const navigate = useNavigate();
  const narrow = useMediaQuery('(max-width: 48em)');

  const formats = useMemo(() => {
    const s = new Set<string>(info?.formats.map((f) => f.name) ?? []);
    repos?.forEach((r) => s.add(r.format));
    return [...s].sort();
  }, [info, repos]);

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return (repos ?? [])
      .filter((r) => format === 'all' || r.format === format)
      .filter((r) => !q || r.name.includes(q) || r.description.toLowerCase().includes(q))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [repos, format, filter]);

  return (
    <>
      <PageHeader
        title="Repositories"
        description="Hosted, proxy and group repositories you can access."
        actions={
          admin && (
            <Button component={Link} to="/repositories/new" leftSection={<IconPlus size={16} />}>
              Create repository
            </Button>
          )
        }
      />

      <Paper p={0}>
        <Group p="sm" justify="space-between" wrap="wrap" gap="sm">
          <SegmentedControl
            size="xs"
            value={format}
            onChange={(v) => {
              const next = new URLSearchParams(params);
              if (v === 'all') next.delete('format');
              else next.set('format', v);
              setParams(next, { replace: true });
            }}
            data={[{ value: 'all', label: 'All formats' }, ...formats.map((f) => ({ value: f, label: formatLabel(f) }))]}
          />
          <TextInput
            size="xs"
            placeholder="Filter by name"
            leftSection={<IconSearch size={14} />}
            value={filter}
            onChange={(e) => setFilter(e.currentTarget.value)}
            w={240}
          />
        </Group>

        {error ? (
          <Stack px="sm" pb="sm">
            <QueryError error={error} retry={refetch} />
          </Stack>
        ) : isPending ? (
          <TableSkeleton rows={6} cols={6} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<IconPackages size={28} stroke={1.5} />}
            title={repos && repos.length > 0 ? 'No matching repositories' : 'No repositories yet'}
            description={
              repos && repos.length > 0
                ? 'Try a different filter.'
                : anonymous
                  ? 'No repositories are readable anonymously. Sign in to see more.'
                  : admin
                    ? 'Create a hosted repository to publish packages, or a proxy to cache a public registry.'
                    : 'You do not have access to any repository yet. Ask an administrator for a role binding.'
            }
            action={
              anonymous ? (
                <Button component={Link} to="/login?return=/repositories" variant="light">
                  Sign in
                </Button>
              ) : (
                admin &&
                !(repos && repos.length > 0) && (
                  <Button component={Link} to="/repositories/new" leftSection={<IconPlus size={16} />}>
                    Create repository
                  </Button>
                )
              )
            }
          />
        ) : narrow ? (
          <Stack gap={0}>
            {rows.map((r) => (
              <UnstyledButton
                key={r.name}
                component={Link}
                to={`/repositories/${r.name}`}
                px="sm"
                py="sm"
                style={{ borderTop: '1px solid var(--mantine-color-default-border)' }}
              >
                <Group gap="sm" wrap="nowrap" align="flex-start">
                  <FormatIcon format={r.format} size={20} />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <Group gap={6}>
                      <Text fw={600} size="sm" c="blue">
                        {r.name}
                      </Text>
                      {r.anonymousRead && <IconWorld size={14} color="var(--mantine-color-dimmed)" />}
                    </Group>
                    {r.description && (
                      <Text size="xs" c="dimmed" lineClamp={1}>
                        {r.description}
                      </Text>
                    )}
                    <Group gap={4} mt={6}>
                      <FormatBadge format={r.format} size="sm" />
                      <KindBadge kind={r.kind} size="sm" />
                      {!r.online && <OnlineBadge online={false} />}
                    </Group>
                  </div>
                </Group>
              </UnstyledButton>
            ))}
          </Stack>
        ) : (
          <Table.ScrollContainer minWidth={860}>
            <Table verticalSpacing="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Format</Table.Th>
                  <Table.Th>Kind</Table.Th>
                  <Table.Th>Blob store</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>URL</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rows.map((r) => (
                  <Table.Tr key={r.name} className="row-link" onClick={() => navigate(`/repositories/${r.name}`)}>
                    <Table.Td>
                      <Group gap="sm" wrap="nowrap">
                        <FormatIcon format={r.format} size={20} />
                        <div style={{ minWidth: 0 }}>
                          <Group gap={6} wrap="nowrap">
                            <Anchor
                              component={Link}
                              to={`/repositories/${r.name}`}
                              fw={600}
                              size="sm"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {r.name}
                            </Anchor>
                            {r.anonymousRead && (
                              <Tooltip label="Readable without signing in" withArrow>
                                <IconWorld size={14} color="var(--mantine-color-dimmed)" />
                              </Tooltip>
                            )}
                          </Group>
                          {r.description && (
                            <Text size="xs" c="dimmed" lineClamp={1} maw={320}>
                              {r.description}
                            </Text>
                          )}
                        </div>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <FormatBadge format={r.format} />
                    </Table.Td>
                    <Table.Td>
                      <KindBadge kind={r.kind} />
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="default" radius="sm" tt="none" fw={500}>
                        {r.blobStore}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <OnlineBadge online={r.online} />
                    </Table.Td>
                    <Table.Td onClick={(e) => e.stopPropagation()}>
                      <CopyText value={r.url} maw={300} />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      {rows.length > 0 && (
        <Text size="xs" c="dimmed" mt="xs">
          {rows.length} of {repos?.length ?? 0} repositories
        </Text>
      )}
    </>
  );
}
