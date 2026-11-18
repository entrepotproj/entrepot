import { Alert, Button, Center, Group, Skeleton, Stack, Table, Text, ThemeIcon } from '@mantine/core';
import { IconAlertTriangle, IconClockPause, IconLock, IconLogin, IconMoodEmpty } from '@tabler/icons-react';
import type { ReactNode } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { ApiError } from '../api/client';
import { describeError } from '../lib/notify';

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <Center py={48}>
      <Stack align="center" gap="xs" maw={420}>
        <ThemeIcon size={52} radius="xl" variant="light" color="gray">
          {icon ?? <IconMoodEmpty size={28} stroke={1.5} />}
        </ThemeIcon>
        <Text fw={600} mt={4}>
          {title}
        </Text>
        {description && (
          <Text size="sm" c="dimmed" ta="center">
            {description}
          </Text>
        )}
        {action && <Group mt="xs">{action}</Group>}
      </Stack>
    </Center>
  );
}

export function SignInPrompt({ message }: { message?: string }) {
  const navigate = useNavigate();
  const location = useLocation();
  return (
    <EmptyState
      icon={<IconLogin size={28} stroke={1.5} />}
      title="Sign in required"
      description={message ?? 'You need to sign in to see this page.'}
      action={
        <Button
          leftSection={<IconLogin size={16} />}
          onClick={() => navigate('/login?return=' + encodeURIComponent(location.pathname + location.search))}
        >
          Sign in
        </Button>
      }
    />
  );
}

/** Shown when the server answers 501 Not Implemented for a feature. */
export function NotAvailable({ feature, compact }: { feature?: string; compact?: boolean }) {
  const description = `${feature ? feature + ': n' : 'N'}ot implemented by this Entrepot server yet. Upgrade the server to use it.`;
  if (compact) {
    return (
      <Alert color="gray" variant="light" icon={<IconClockPause size={18} />} title="Not available yet" my="xs">
        <Text size="sm">{description}</Text>
      </Alert>
    );
  }
  return (
    <EmptyState
      icon={<IconClockPause size={28} stroke={1.5} />}
      title="This feature isn't available on this server yet"
      description={description}
    />
  );
}

/** Renders a query error: 401 prompts to sign in, 403 shows "not permitted", 501 "not available yet". */
export function QueryError({
  error,
  retry,
  feature,
  compact,
}: {
  error: unknown;
  retry?: () => void;
  feature?: string;
  compact?: boolean;
}) {
  if (error instanceof ApiError && error.notImplemented) return <NotAvailable feature={feature} compact={compact} />;
  if (error instanceof ApiError && error.unauthorized) return <SignInPrompt />;
  if (error instanceof ApiError && error.forbidden) {
    return (
      <EmptyState
        icon={<IconLock size={28} stroke={1.5} />}
        title="Not permitted"
        description={error.message || 'You do not have permission to view this.'}
      />
    );
  }
  const { title, message } = describeError(error);
  return (
    <Alert color="red" variant="light" title={title} icon={<IconAlertTriangle />} my="md">
      <Group justify="space-between" align="center">
        <Text size="sm">{message}</Text>
        {retry && (
          <Button size="xs" variant="white" color="red" onClick={retry}>
            Retry
          </Button>
        )}
      </Group>
    </Alert>
  );
}

export function TableSkeleton({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <Table>
      <Table.Tbody>
        {Array.from({ length: rows }).map((_, i) => (
          <Table.Tr key={i}>
            {Array.from({ length: cols }).map((__, j) => (
              <Table.Td key={j}>
                <Skeleton height={14} width={j === 0 ? '70%' : '50%'} radius="sm" />
              </Table.Td>
            ))}
          </Table.Tr>
        ))}
      </Table.Tbody>
    </Table>
  );
}
