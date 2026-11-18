import { Group, Paper, Skeleton, Stack, Tabs, Text } from '@mantine/core';
import { IconChartAreaLine } from '@tabler/icons-react';
import { useState } from 'react';
import type { Repository } from '../../api/client';
import { useRepositoryMetrics } from '../../api/queries';
import { QueryError } from '../../components/states';
import { UsageChart, type UsageMetric } from '../../components/usage/UsageChart';
import { RangeSelector, UsageKpis } from '../../components/usage/UsageKpis';
import { rangeLabel, useUsageRange } from '../../lib/usage';
import { bucketName, PanelTitle } from '../dashboard/Panels';

export function UsageTab({ repository }: { repository: Repository }) {
  const [range, setRange] = useUsageRange();
  const { data, error, isPending, refetch } = useRepositoryMetrics(repository.name, range);
  const proxy = repository.kind === 'proxy';
  const [metric, setMetric] = useState<UsageMetric>('traffic');

  return (
    <Stack gap="md">
      <Group justify="space-between" wrap="wrap" gap="xs">
        <Text size="sm" c="dimmed">
          Client traffic for <b>{repository.name}</b> over {rangeLabel(range)}
          {proxy ? ', including cache efficiency against the upstream' : ''}. Refreshes every 30 seconds.
        </Text>
        <RangeSelector value={range} onChange={setRange} />
      </Group>
      {error ? (
        <QueryError error={error} retry={refetch} feature="Usage metrics" compact />
      ) : (
        <>
          <UsageKpis totals={data?.totals} requestRate={data?.requestRate} loading={isPending} />
          {data ? (
            <Paper p="md">
              <PanelTitle
                title="Traffic"
                icon={IconChartAreaLine}
                description={`Per ${bucketName(data.bucketSeconds)}`}
                right={
                  <Tabs value={metric} onChange={(v) => setMetric((v as UsageMetric) ?? 'traffic')} variant="pills" radius="md">
                    <Tabs.List>
                      <Tabs.Tab value="traffic" fz="xs" px={10} py={4}>
                        Requests
                      </Tabs.Tab>
                      <Tabs.Tab value="bytes" fz="xs" px={10} py={4}>
                        Data served
                      </Tabs.Tab>
                    </Tabs.List>
                  </Tabs>
                }
              />
              <UsageChart
                series={data.series}
                bucketSeconds={data.bucketSeconds}
                metric={metric}
                height={280}
                emptyHint={`Nobody has used ${repository.name} in this period. Point a client at it with the setup instructions above.`}
              />
            </Paper>
          ) : (
            <Skeleton h={340} radius="md" />
          )}
        </>
      )}
    </Stack>
  );
}
