import { Alert, Anchor } from '@mantine/core';
import { IconInfoCircle } from '@tabler/icons-react';
import { Link } from 'react-router';
import { api, unwrap, unwrapVoid } from '../api/client';
import { qk } from '../api/queries';
import { PageHeader } from '../components/PageHeader';
import { SignInPrompt } from '../components/states';
import { TokenManager } from '../components/TokenManager';
import { useAuth } from '../lib/auth';

export function TokensPage() {
  const { me, anonymous, loading, admin } = useAuth();
  if (loading) return null;
  if (anonymous) return <SignInPrompt message="Sign in to manage your API tokens." />;
  const header = (
    <PageHeader
      title="API tokens"
      description="Personal tokens for package clients, scripts and the API. They act with your permissions, optionally restricted by scope."
    />
  );
  if (!me?.userId) {
    return (
      <>
        {header}
        <Alert color="blue" variant="light" icon={<IconInfoCircle size={18} />} title="Tokens need a user account">
          You are signed in as <b>{me?.name}</b> ({me?.kind}), which cannot own API tokens.{' '}
          {admin ? (
            <>
              Create a{' '}
              <Anchor component={Link} to="/admin/service-accounts">
                service account
              </Anchor>{' '}
              and issue tokens for it instead.
            </>
          ) : (
            'Sign in with single sign-on to create personal tokens.'
          )}
        </Alert>
      </>
    );
  }
  return (
    <>
      {header}
      <TokenManager
        queryKey={qk.tokens}
        list={() => unwrap(api.GET('/tokens'))}
        create={(body) => unwrap(api.POST('/tokens', { body }))}
        revoke={(id) => unwrapVoid(api.DELETE('/tokens/{id}', { params: { path: { id } } }))}
        emptyHint="Create a token to authenticate pip, npm, docker or scripts."
      />
    </>
  );
}
