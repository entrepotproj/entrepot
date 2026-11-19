import { Group, Paper, Select, Stack, Text } from '@mantine/core';
import { useMemo, useState } from 'react';
import { apiUrl, type Repository } from '../../api/client';
import { ActivityTable, useActivity } from '../../components/ActivityTable';
import { ExportCsvButton } from '../../components/LogFilters';

type Kind = 'download' | 'upload' | 'delete';

/** Recent downloads, uploads and deletes of one repository (repository administrators). */
export function ActivityTab({ repository }: { repository: Repository }) {
  const [kind, setKind] = useState<string | null>(null);
  const filters = useMemo(
    () => ({ repository: repository.name, kind: (kind ?? undefined) as Kind | undefined }),
    [repository.name, kind],
  );
  const query = useActivity(filters);
  return (
    <Stack gap="sm">
      <Group justify="space-between" wrap="wrap" gap="xs">
        <Text size="sm" c="dimmed">
          Who downloaded, uploaded or deleted what in {repository.name}, newest first.
        </Text>
        <Group gap="xs">
          <Select
            size="xs"
            placeholder="All kinds"
            data={[
              { value: 'download', label: 'Downloads' },
              { value: 'upload', label: 'Uploads' },
              { value: 'delete', label: 'Deletes' },
            ]}
            value={kind}
            onChange={setKind}
            clearable
            w={140}
            aria-label="Kind"
          />
          <ExportCsvButton href={apiUrl('/activity', { ...filters, format: 'csv' })} max={1000} />
        </Group>
      </Group>
      <Paper p={0}>
        <ActivityTable
          query={query}
          showRepository={false}
          emptyHint={kind ? `No ${kind}s recorded yet.` : 'Nothing has been downloaded, uploaded or deleted here yet.'}
        />
      </Paper>
    </Stack>
  );
}
