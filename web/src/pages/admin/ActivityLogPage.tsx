import { Button, Group, Paper, Select, Stack } from '@mantine/core';
import { IconRefresh } from '@tabler/icons-react';
import { useMemo } from 'react';
import { apiUrl } from '../../api/client';
import { useRepositories } from '../../api/queries';
import { ActivityTable, useActivity } from '../../components/ActivityTable';
import { formatLabel } from '../../components/badges';
import {
  ClearFiltersButton,
  DateRangeFilter,
  DebouncedParamInput,
  ExportCsvButton,
  localToIso,
  useParamState,
} from '../../components/LogFilters';
import { PageHeader } from '../../components/PageHeader';

const FILTER_KEYS = ['repository', 'kind', 'actor', 'path', 'from', 'to'];
type Kind = 'download' | 'upload' | 'delete';

export default function ActivityLogPage() {
  const [repository, setRepository] = useParamState('repository');
  const [kind, setKind] = useParamState('kind');
  const [actor] = useParamState('actor');
  const [path] = useParamState('path');
  const [from] = useParamState('from');
  const [to] = useParamState('to');
  const { data: repos } = useRepositories();

  const filters = useMemo(
    () => ({
      repository: repository || undefined,
      kind: (kind || undefined) as Kind | undefined,
      actor: actor || undefined,
      path: path || undefined,
      from: localToIso(from),
      to: localToIso(to),
    }),
    [repository, kind, actor, path, from, to],
  );
  const query = useActivity(filters);

  const repoOptions = useMemo(() => {
    const byFormat = new Map<string, string[]>();
    for (const r of [...(repos ?? [])].sort((a, b) => a.name.localeCompare(b.name))) {
      byFormat.set(r.format, [...(byFormat.get(r.format) ?? []), r.name]);
    }
    return [...byFormat.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([f, items]) => ({ group: formatLabel(f), items }));
  }, [repos]);

  const active = [repository, kind, actor, path, from, to].some(Boolean);

  return (
    <>
      <PageHeader
        title="Activity"
        description="Downloads, uploads and deletes across all repositories, newest first."
        actions={
          <>
            <Button
              variant="default"
              leftSection={<IconRefresh size={16} />}
              onClick={() => query.refetch()}
              loading={query.isRefetching && !query.isFetchingNextPage}
            >
              Refresh
            </Button>
            <ExportCsvButton href={apiUrl('/activity', { ...filters, format: 'csv' })} max={1000} />
          </>
        }
      />
      <Paper p={0}>
        <Stack gap={0}>
          <Group p="sm" gap="xs" align="flex-end" wrap="wrap" style={{ borderBottom: '1px solid var(--mantine-color-default-border)' }}>
            <Select
              size="xs"
              label="Repository"
              placeholder="All repositories"
              data={repoOptions}
              value={repository || null}
              onChange={(v) => setRepository(v ?? '')}
              searchable
              clearable
              w={180}
              nothingFoundMessage="No repository"
            />
            <Select
              size="xs"
              label="Kind"
              placeholder="All kinds"
              data={[
                { value: 'download', label: 'Downloads' },
                { value: 'upload', label: 'Uploads' },
                { value: 'delete', label: 'Deletes' },
              ]}
              value={kind || null}
              onChange={(v) => setKind(v ?? '')}
              clearable
              w={120}
            />
            <DebouncedParamInput param="actor" label="Actor" placeholder="Name contains…" w={140} />
            <DebouncedParamInput param="path" label="Path" placeholder="Path contains…" w={160} mono />
            <DateRangeFilter />
            <ClearFiltersButton keys={FILTER_KEYS} active={active} />
          </Group>
          <ActivityTable query={query} />
        </Stack>
      </Paper>
    </>
  );
}
