import {
  Alert,
  Anchor,
  Box,
  Button,
  Center,
  Collapse,
  Divider,
  Paper,
  PasswordInput,
  Skeleton,
  Stack,
  Text,
  Title,
} from '@mantine/core';
import { IconAlertTriangle, IconKey, IconLogin } from '@tabler/icons-react';
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { loginUrl, tokenLogin } from '../api/client';
import { useSystemInfo } from '../api/queries';
import { Logo } from '../components/AppLayout';
import { describeError } from '../lib/notify';

function safeReturn(p: string | null): string {
  if (!p || !p.startsWith('/') || p.startsWith('//') || p.startsWith('/\\') || p.startsWith('/login')) return '/repositories';
  return p;
}

export function LoginPage() {
  const [params] = useSearchParams();
  const returnTo = safeReturn(params.get('return'));
  const { data: info, isPending } = useSystemInfo();
  const oidc = info?.oidc.enabled;
  const [showToken, setShowToken] = useState(false);
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const qc = useQueryClient();
  const navigate = useNavigate();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await tokenLogin(token.trim());
      qc.clear();
      navigate(returnTo, { replace: true });
    } catch (err) {
      setError(describeError(err).message);
    } finally {
      setBusy(false);
    }
  };

  const tokenOpen = showToken || (!isPending && !oidc);

  return (
    <Box
      mih="100vh"
      style={{
        background:
          'radial-gradient(circle at 20% 10%, var(--mantine-color-blue-light), transparent 45%), var(--mantine-color-body)',
      }}
    >
      <Center mih="100vh" p="md">
        <Paper w={400} maw="100%" p="xl" shadow="md">
          <Stack gap="lg">
            <Stack gap={6} align="center">
              <Logo />
              <Title order={3} ta="center" mt="sm">
                Sign in
              </Title>
              <Text size="sm" c="dimmed" ta="center">
                Manage repositories, publish packages and create API tokens.
              </Text>
            </Stack>

            {isPending ? (
              <Skeleton height={40} />
            ) : (
              oidc && (
                <Button
                  component="a"
                  href={loginUrl(returnTo)}
                  size="md"
                  leftSection={<IconLogin size={18} />}
                  fullWidth
                >
                  Sign in with {info?.oidc.displayName || 'single sign-on'}
                </Button>
              )
            )}

            {oidc && !showToken && (
              <>
                <Divider label="or" labelPosition="center" />
                <Button
                  variant="default"
                  leftSection={<IconKey size={16} />}
                  onClick={() => setShowToken(true)}
                  fullWidth
                >
                  Sign in with an API token
                </Button>
              </>
            )}

            <Collapse in={tokenOpen}>
              <form onSubmit={submit}>
                <Stack gap="sm">
                  {oidc && <Divider label="API token" labelPosition="center" />}
                  <PasswordInput
                    label="API token"
                    description="An Entrepot API token (ent_…) or the bootstrap token."
                    placeholder="ent_…"
                    value={token}
                    onChange={(e) => setToken(e.currentTarget.value)}
                    autoFocus={!oidc}
                    autoComplete="off"
                    required
                  />
                  {error && (
                    <Alert color="red" variant="light" icon={<IconAlertTriangle size={18} />} p="xs">
                      {error}
                    </Alert>
                  )}
                  <Button type="submit" loading={busy} disabled={!token.trim()} leftSection={<IconKey size={16} />}>
                    Sign in with token
                  </Button>
                </Stack>
              </form>
            </Collapse>

            <Text size="sm" ta="center" c="dimmed">
              <Anchor component={Link} to={returnTo} size="sm">
                Continue without signing in
              </Anchor>
            </Text>
          </Stack>
        </Paper>
      </Center>
    </Box>
  );
}
