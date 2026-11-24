import { Anchor, Button, Group, Paper, Select, Stack, Table, Text, TextInput } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconChevronLeft, IconChevronRight, IconSearch } from '@tabler/icons-react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { api, unwrap, type Component } from '../api/client';
import { useRepositories, useSystemInfo } from '../api/queries';
import { FormatBadge, formatLabel, SeverityBadge, SEVERITIES } from '../components/badges';
import { PageHeader } from '../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../components/states';
import { formatRelative } from '../lib/format';

const PAGE = 50;

export function SearchPage() {
  const [params, setParams] = useSearchParams();
  const q = params.get('q') ?? '';
  const format = params.get('format') ?? '';
  const repository = params.get('repository') ?? '';
  const quarantined = params.get('quarantined') === 'true';
  const scanState = params.get('scanState') === 'vulnerable' ? 'vulnerable' : '';
  // The security filter is one of: all, vulnerable, quarantined.
  const security = quarantined ? 'quarantined' : scanState;
  const offset = Number(params.get('offset') ?? 0) || 0;
  const [debounced] = useDebouncedValue(q.trim(), 250);
  const { data: info } = useSystemInfo();
  const { data: repos } = useRepositories();
  const navigate = useNavigate();

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== 'offset') next.delete('offset');
    setParams(next, { replace: true });
  };

  const setSecurity = (v: string) => {
    const next = new URLSearchParams(params);
    next.delete('scanState');
    next.delete('quarantined');
    next.delete('offset');
    if (v === 'vulnerable') next.set('scanState', 'vulnerable');
    if (v === 'quarantined') next.set('quarantined', 'true');
    setParams(next, { replace: true });
  };

  const { data, isPending, isFetching, error, refetch } = useQuery({
    queryKey: ['search', debounced, format, repository, security, offset],
    queryFn: () =>
      unwrap(
        api.GET('/search', {
          params: {
            query: {
              q: debounced || undefined,
              format: format || undefined,
              repository: repository || undefined,
              scanState: scanState ? 'vulnerable' : undefined,
              quarantined: quarantined ? true : undefined,
              withFindings: security ? true : undefined,
              limit: PAGE,
              offset,
            },
          },
        }),
      ),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader title="Search" description="Find components (packages and versions) across all repositories you can read." />
      <Paper p={0}>
        <Group p="sm" gap="sm" wrap="wrap">
          <TextInput
            placeholder="Package name"
            leftSection={<IconSearch size={16} />}
            value={q}
            onChange={(e) => set('q', e.currentTarget.value)}
            style={{ flex: 1, minWidth: 220 }}
            autoFocus
          />
          <Select
            placeholder="All formats"
            data={(info?.formats ?? []).map((f) => ({ value: f.name, label: formatLabel(f.name) }))}
            value={format || null}
            onChange={(v) => set('format', v ?? '')}
            clearable
            w={160}
          />
          <Select
            placeholder="All repositories"
            data={(repos ?? [])
              .filter((r) => !format || r.format === format)
              .map((r) => r.name)
              .sort()}
            value={repository || null}
            onChange={(v) => set('repository', v ?? '')}
            clearable
            searchable
            w={220}
          />
          <Select
            placeholder="Any security state"
            data={[
              { value: 'vulnerable', label: 'Vulnerable' },
              { value: 'quarantined', label: 'Quarantined' },
            ]}
            value={security || null}
            onChange={(v) => setSecurity(v ?? '')}
            clearable
            w={180}
          />
        </Group>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={6} cols={4} />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<IconSearch size={28} stroke={1.5} />}
            title="No components found"
            description={debounced ? `Nothing matches “${debounced}”.` : 'No components in the repositories you can read.'}
          />
        ) : (
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Version</Table.Th>
                <Table.Th>Format</Table.Th>
                <Table.Th>Repository</Table.Th>
                {security && <Table.Th>Findings</Table.Th>}
                <Table.Th>Updated</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {data.map((c) => (
                <Table.Tr key={c.id} className="row-link" onClick={() => navigate(`/components/${c.id}`)}>
                  <Table.Td>
                    <Anchor component={Link} to={`/components/${c.id}`} size="sm" fw={500} onClick={(e) => e.stopPropagation()}>
                      {c.name}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {c.version || '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <FormatBadge format={c.format} size="sm" />
                  </Table.Td>
                  <Table.Td>
                    <Anchor
                      component={Link}
                      to={`/repositories/${c.repository}`}
                      size="sm"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {c.repository}
                    </Anchor>
                  </Table.Td>
                  {security && (
                    <Table.Td>
                      <FindingsCell component={c} />
                    </Table.Td>
                  )}
                  <Table.Td>
                    <Text size="sm" c="dimmed">
                      {formatRelative(c.updatedAt)}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Paper>
      <Group justify="flex-end" mt="sm" gap="xs">
        <Button
          size="xs"
          variant="default"
          leftSection={<IconChevronLeft size={14} />}
          disabled={offset === 0 || isFetching}
          onClick={() => set('offset', String(Math.max(0, offset - PAGE)))}
        >
          Previous
        </Button>
        <Button
          size="xs"
          variant="default"
          rightSection={<IconChevronRight size={14} />}
          disabled={!data || data.length < PAGE || isFetching}
          onClick={() => set('offset', String(offset + PAGE))}
        >
          Next
        </Button>
      </Group>
    </>
  );
}

/** Only http(s) advisory links are rendered as links; the URL comes from a scanner. */
function safeHref(url: string): string | undefined {
  return /^https?:\/\//i.test(url) ? url : undefined;
}

/** Unwaived finding counts by severity and the most severe findings, linked to their advisories. */
function FindingsCell({ component: c }: { component: Component }) {
  const counts = c.findingCounts;
  const findings = c.findings ?? [];
  const total = counts ? SEVERITIES.reduce((n, s) => n + counts[s], 0) : 0;
  if (!counts || total === 0) {
    return (
      <Text size="sm" c="dimmed">
        {c.quarantined ? 'Quarantined' : '—'}
      </Text>
    );
  }
  return (
    <Stack gap={4} onClick={(e) => e.stopPropagation()}>
      <Group gap={4}>
        {SEVERITIES.filter((s) => counts[s] > 0).map((s) => (
          <SeverityBadge key={s} severity={s} size="sm">
            {counts[s]} {s}
          </SeverityBadge>
        ))}
      </Group>
      <Group gap="xs">
        {findings.map((f) => {
          const href = safeHref(f.url);
          return href ? (
            <Anchor key={`${f.vulnId}${f.package}`} href={href} target="_blank" rel="noopener noreferrer" size="xs" ff="monospace" title={f.title}>
              {f.vulnId}
            </Anchor>
          ) : (
            <Text key={`${f.vulnId}${f.package}`} size="xs" ff="monospace" title={f.title}>
              {f.vulnId}
            </Text>
          );
        })}
        {total > findings.length && (
          <Anchor component={Link} to={`/components/${c.id}`} size="xs">
            +{total - findings.length} more
          </Anchor>
        )}
      </Group>
    </Stack>
  );
}
