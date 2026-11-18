import { Alert, Anchor, Badge, Box, Button, Grid, Group, Skeleton, Stack, Text, Title, Tooltip } from '@mantine/core';
import { IconEye, IconLogin, IconRefresh, IconWorld } from '@tabler/icons-react';
import { useEffect } from 'react';
import { Link } from 'react-router';
import { useMetricsOverview } from '../api/queries';
import { QueryError } from '../components/states';
import { RangeSelector, UsageKpis } from '../components/usage/UsageKpis';
import { useAuth } from '../lib/auth';
import { rangeLabel, useUsageRange } from '../lib/usage';
import { ContentPanel, SecurityPanel, StoragePanel, TopRepositoriesPanel, TrafficPanel } from './dashboard/Panels';
import { RepositoryExplorer } from './dashboard/RepositoryExplorer';

function displayName(name: string): string {
  return name.replace(/^sa:/, '');
}

function greeting(): string {
  const h = new Date().getHours();
  return h < 5 ? 'Welcome back' : h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
}

export function DashboardPage() {
  const { me, anonymous, admin, loading } = useAuth();
  const [range, setRange] = useUsageRange();
  const { data, error, isPending, isFetching, refetch, dataUpdatedAt } = useMetricsOverview(range, !loading);

  useEffect(() => {
    document.title = 'Dashboard · Entrepot';
  }, []);

  const all = data?.scope === 'all';

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-end" wrap="wrap" gap="sm">
        <div>
          {loading ? (
            <Skeleton h={32} w={280} />
          ) : (
            <Title order={2} fw={650}>
              {anonymous ? 'Welcome to Entrepot' : `${greeting()}, ${displayName(me?.name ?? '')}`}
            </Title>
          )}
          <Group gap={8} mt={4}>
            <Text size="sm" c="dimmed">
              Usage over {rangeLabel(range)}
            </Text>
            {data && (
              <Tooltip
                label={
                  all
                    ? 'You are an administrator: totals include every repository.'
                    : 'Totals only include repositories you are allowed to read.'
                }
                withArrow
                multiline
                w={240}
              >
                <Badge
                  size="sm"
                  variant="light"
                  color={all ? 'grape' : 'gray'}
                  radius="sm"
                  tt="none"
                  leftSection={all ? <IconWorld size={12} /> : <IconEye size={12} />}
                >
                  {all ? 'Showing all repositories' : anonymous ? 'Showing public repositories' : 'Showing repositories you can access'}
                </Badge>
              </Tooltip>
            )}
          </Group>
        </div>
        <Group gap="xs" wrap="nowrap">
          {dataUpdatedAt > 0 && (
            <Tooltip label="Refreshes every 30 seconds while this tab is visible" withArrow>
              <Text size="xs" c="dimmed" visibleFrom="xs" style={{ whiteSpace: 'nowrap' }}>
                Updated {new Date(dataUpdatedAt).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
              </Text>
            </Tooltip>
          )}
          <Tooltip label="Refresh now" withArrow>
            <Button
              variant="default"
              size="xs"
              px={8}
              onClick={() => refetch()}
              loading={isFetching && !isPending}
              aria-label="Refresh"
            >
              <IconRefresh size={14} />
            </Button>
          </Tooltip>
          <RangeSelector value={range} onChange={setRange} />
        </Group>
      </Group>

      {anonymous && !loading && (
        <Alert variant="light" color="blue" icon={<IconLogin size={18} />} p="sm">
          <Group justify="space-between" wrap="wrap" gap="xs">
            <Text size="sm">
              You are browsing as a guest: you see public repositories only.{' '}
              <Text span size="sm" c="dimmed">
                Sign in to see private repositories, publish packages and create API tokens.
              </Text>
            </Text>
            <Button component={Link} to="/login?return=/" size="xs" leftSection={<IconLogin size={14} />}>
              Sign in
            </Button>
          </Group>
        </Alert>
      )}

      {error ? (
        <QueryError error={error} retry={refetch} feature="Usage metrics" compact />
      ) : (
        <>
          <UsageKpis totals={data?.totals} requestRate={data?.requestRate} loading={isPending} />

          <Grid gutter="md">
            <Grid.Col span={{ base: 12, lg: 8 }}>
              {data ? <TrafficPanel overview={data} /> : <Skeleton h={340} radius="md" />}
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 4 }}>
              {data ? <SecurityPanel scan={data.scan} admin={admin} /> : <Skeleton h={340} radius="md" />}
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 7 }}>
              {data ? <TopRepositoriesPanel rows={data.topRepositories} range={data.range} /> : <Skeleton h={260} radius="md" />}
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 5 }}>
              {data ? <ContentPanel inventory={data.inventory} /> : <Skeleton h={260} radius="md" />}
            </Grid.Col>
            {data?.storage && (
              <Grid.Col span={12}>
                <StoragePanel stores={data.storage} />
              </Grid.Col>
            )}
          </Grid>
        </>
      )}

      <Box mt="sm">
        <RepositoryExplorer anonymous={anonymous} admin={admin} />
      </Box>
      {!anonymous && (
        <Text size="xs" c="dimmed" ta="center">
          Need credentials for a client or CI job?{' '}
          <Anchor component={Link} to="/tokens" size="xs">
            Create an API token
          </Anchor>
          .
        </Text>
      )}
    </Stack>
  );
}
