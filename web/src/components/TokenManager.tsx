import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Checkbox,
  Code,
  CopyButton,
  Group,
  Modal,
  NumberInput,
  Paper,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core';
import { IconAlertTriangle, IconCheck, IconCopy, IconKey, IconPlus, IconTrash } from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import type { Action, ApiToken, ApiTokenCreated, ApiTokenInput } from '../api/client';
import { formatDate, formatRelative } from '../lib/format';
import { notifySuccess } from '../lib/notify';
import { ConfirmDelete } from './ConfirmDelete';
import { EmptyState, QueryError, TableSkeleton } from './states';

const SCOPES: { value: Action; label: string; help: string }[] = [
  { value: 'read', label: 'read', help: 'Download and browse' },
  { value: 'write', label: 'write', help: 'Publish and upload' },
  { value: 'delete', label: 'delete', help: 'Delete artifacts' },
  { value: 'admin', label: 'admin', help: 'Administer repositories' },
];

function CreateTokenModal({
  opened,
  onClose,
  onCreate,
  loading,
}: {
  opened: boolean;
  onClose: () => void;
  onCreate: (input: ApiTokenInput) => void;
  loading: boolean;
}) {
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<Action[]>(['read']);
  const [days, setDays] = useState<number | ''>(90);
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Create API token</Text>} centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onCreate({ name: name.trim(), scopes: scopes.length ? scopes : undefined, expiresInDays: days === '' ? undefined : days });
        }}
      >
        <Stack>
          <TextInput
            label="Name"
            description="What the token is used for, e.g. laptop or ci-deploy."
            value={name}
            onChange={(e) => setName(e.currentTarget.value)}
            required
            data-autofocus
          />
          <Checkbox.Group
            label="Scopes"
            description="Restrict what the token may do. The token never has more access than its owner. Leave all unchecked for unrestricted."
            value={scopes}
            onChange={(v) => setScopes(v as Action[])}
          >
            <Stack gap={6} mt={8}>
              {SCOPES.map((s) => (
                <Checkbox
                  key={s.value}
                  value={s.value}
                  label={
                    <Text size="sm">
                      <b>{s.label}</b>{' '}
                      <Text span c="dimmed" size="sm">
                        — {s.help}
                      </Text>
                    </Text>
                  }
                />
              ))}
            </Stack>
          </Checkbox.Group>
          <NumberInput
            label="Expires in (days)"
            description="Leave empty for a token that never expires."
            min={1}
            value={days}
            onChange={(v) => setDays(typeof v === 'number' ? v : '')}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={loading} disabled={!name.trim()} leftSection={<IconKey size={16} />}>
              Create token
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

export function SecretModal({ created, onClose }: { created: ApiTokenCreated | null; onClose: () => void }) {
  return (
    <Modal
      opened={!!created}
      onClose={onClose}
      title={<Text fw={600}>Token created</Text>}
      centered
      size="lg"
      closeOnClickOutside={false}
    >
      {created && (
        <Stack>
          <Alert color="orange" variant="light" icon={<IconAlertTriangle size={18} />}>
            Copy the token now. It is shown only once and cannot be retrieved later.
          </Alert>
          <Group gap="xs" wrap="nowrap">
            <Code block style={{ flex: 1, wordBreak: 'break-all', whiteSpace: 'pre-wrap' }} fz="sm">
              {created.secret}
            </Code>
            <CopyButton value={created.secret}>
              {({ copied, copy }) => (
                <Button
                  onClick={copy}
                  color={copied ? 'teal' : undefined}
                  leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                >
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              )}
            </CopyButton>
          </Group>
          <Text size="sm" c="dimmed">
            Use it as a bearer token, as the password with any username for package clients, or to sign in to this UI.
          </Text>
          <Group justify="flex-end">
            <Button onClick={onClose}>Done</Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}

function expiryBadge(t: ApiToken) {
  if (!t.expiresAt) return <Text size="sm" c="dimmed">Never</Text>;
  const expired = new Date(t.expiresAt).getTime() < Date.now();
  return expired ? (
    <Badge color="red" variant="light" radius="sm">
      Expired
    </Badge>
  ) : (
    <Text size="sm" title={formatDate(t.expiresAt)}>
      {formatRelative(t.expiresAt)}
    </Text>
  );
}

/** Lists, creates and revokes API tokens for the caller or a service account. */
export function TokenManager({
  queryKey,
  list,
  create,
  revoke,
  emptyHint,
}: {
  queryKey: readonly unknown[];
  list: () => Promise<ApiToken[]>;
  create: (input: ApiTokenInput) => Promise<ApiTokenCreated>;
  revoke: (id: string) => Promise<void>;
  emptyHint?: string;
}) {
  const qc = useQueryClient();
  const { data, isPending, error, refetch } = useQuery({ queryKey, queryFn: list });
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  const [revoking, setRevoking] = useState<ApiToken | null>(null);

  const createM = useMutation({
    mutationFn: create,
    onSuccess: (c) => {
      setCreating(false);
      setCreated(c);
      qc.invalidateQueries({ queryKey });
    },
  });
  const revokeM = useMutation({
    mutationFn: (id: string) => revoke(id),
    onSuccess: () => {
      notifySuccess(`Token ${revoking?.name} revoked`);
      setRevoking(null);
      qc.invalidateQueries({ queryKey });
    },
  });

  if (error) return <QueryError error={error} retry={refetch} />;

  return (
    <>
      <Paper p={0}>
        <Group justify="space-between" p="sm">
          <Text size="sm" c="dimmed" px={4}>
            {data ? `${data.length} token${data.length === 1 ? '' : 's'}` : ''}
          </Text>
          <Button size="xs" leftSection={<IconPlus size={14} />} onClick={() => setCreating(true)}>
            Create token
          </Button>
        </Group>
        {isPending ? (
          <TableSkeleton rows={3} cols={5} />
        ) : data.length === 0 ? (
          <EmptyState icon={<IconKey size={28} stroke={1.5} />} title="No API tokens" description={emptyHint} />
        ) : (
          <Table.ScrollContainer minWidth={720}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Token</Table.Th>
                  <Table.Th>Scopes</Table.Th>
                  <Table.Th>Created</Table.Th>
                  <Table.Th>Last used</Table.Th>
                  <Table.Th>Expires</Table.Th>
                  <Table.Th w={50} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.map((t) => (
                  <Table.Tr key={t.id}>
                    <Table.Td>
                      <Text size="sm" fw={500}>
                        {t.name}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" ff="monospace" c="dimmed">
                        {t.hint}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {t.scopes.length === 0 ? (
                          <Badge size="sm" variant="light" color="gray" radius="sm">
                            unrestricted
                          </Badge>
                        ) : (
                          t.scopes.map((s) => (
                            <Badge key={s} size="sm" variant="light" radius="sm" color={s === 'admin' ? 'grape' : 'blue'}>
                              {s}
                            </Badge>
                          ))
                        )}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" title={formatDate(t.createdAt)}>
                        {formatRelative(t.createdAt)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c={t.lastUsedAt ? undefined : 'dimmed'} title={formatDate(t.lastUsedAt)}>
                        {t.lastUsedAt ? formatRelative(t.lastUsedAt) : 'Never'}
                      </Text>
                    </Table.Td>
                    <Table.Td>{expiryBadge(t)}</Table.Td>
                    <Table.Td>
                      <Tooltip label="Revoke">
                        <ActionIcon variant="subtle" color="red" onClick={() => setRevoking(t)} aria-label="Revoke token">
                          <IconTrash size={16} />
                        </ActionIcon>
                      </Tooltip>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      {creating && (
        <CreateTokenModal
          opened={creating}
          onClose={() => setCreating(false)}
          onCreate={(i) => createM.mutate(i)}
          loading={createM.isPending}
        />
      )}
      <SecretModal created={created} onClose={() => setCreated(null)} />
      <ConfirmDelete
        opened={!!revoking}
        onClose={() => setRevoking(null)}
        onConfirm={() => revoking && revokeM.mutate(revoking.id)}
        loading={revokeM.isPending}
        title="Revoke token"
        confirmLabel="Revoke"
      >
        Revoke <b>{revoking?.name}</b>? Clients and sessions using it will stop working immediately.
      </ConfirmDelete>
    </>
  );
}
