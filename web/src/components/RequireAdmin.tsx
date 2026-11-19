import { Center, Loader } from '@mantine/core';
import { IconLock } from '@tabler/icons-react';
import type { ReactNode } from 'react';
import { useAuth } from '../lib/auth';
import { EmptyState, SignInPrompt } from './states';

export function RequireAdmin({ children }: { children: ReactNode }) {
  const { loading, anonymous, admin } = useAuth();
  if (loading) {
    return (
      <Center py={80}>
        <Loader size="sm" />
      </Center>
    );
  }
  if (anonymous) return <SignInPrompt message="This page is for administrators. Sign in to continue." />;
  if (!admin) {
    return (
      <EmptyState
        icon={<IconLock size={28} stroke={1.5} />}
        title="Not permitted"
        description="This page requires administrator access."
      />
    );
  }
  return <>{children}</>;
}
