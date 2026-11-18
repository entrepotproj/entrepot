import { Badge, Group, Paper, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { IconRobot, IconSearch, IconUser, IconUsers } from '@tabler/icons-react';
import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { api, unwrap } from '../../api/client';
import { qk } from '../../api/queries';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { formatDate, formatRelative } from '../../lib/format';

export default function UsersPage() {
  const { data, isPending, error, refetch } = useQuery({ queryKey: qk.users, queryFn: () => unwrap(api.GET('/users')) });
  const [q, setQ] = useState('');
  const rows = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (data ?? []).filter(
      (u) =>
        !s ||
        u.username.toLowerCase().includes(s) ||
        u.email.toLowerCase().includes(s) ||
        u.displayName.toLowerCase().includes(s) ||
        u.groups.some((g) => g.toLowerCase().includes(s)),
    );
  }, [data, q]);
  return (
    <>
      <PageHeader
        title="Users"
        description="Users who have signed in with single sign-on, and service accounts. Access is granted with role bindings."
      />
      <Paper p={0}>
        <Group p="sm">
          <TextInput
            size="xs"
            w={280}
            placeholder="Filter by name, email or group"
            leftSection={<IconSearch size={14} />}
            value={q}
            onChange={(e) => setQ(e.currentTarget.value)}
          />
        </Group>
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={4} cols={5} />
        ) : rows.length === 0 ? (
          <EmptyState icon={<IconUsers size={28} stroke={1.5} />} title="No users" description="Users appear after their first sign-in." />
        ) : (
          <Table.ScrollContainer minWidth={800}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Username</Table.Th>
                  <Table.Th>Name / email</Table.Th>
                  <Table.Th>Groups</Table.Th>
                  <Table.Th>Issuer</Table.Th>
                  <Table.Th>Last sign-in</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rows.map((u) => (
                  <Table.Tr key={u.id}>
                    <Table.Td>
                      <Group gap={6} wrap="nowrap">
                        {u.serviceAccount ? <IconRobot size={16} stroke={1.5} /> : <IconUser size={16} stroke={1.5} />}
                        <Text size="sm" fw={600}>
                          {u.username}
                        </Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{u.displayName || '—'}</Text>
                      {u.email && (
                        <Text size="xs" c="dimmed">
                          {u.email}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {u.groups.length === 0 && (
                          <Text size="sm" c="dimmed">
                            —
                          </Text>
                        )}
                        {u.groups.slice(0, 6).map((g) => (
                          <Badge key={g} size="sm" variant="dot" tt="none">
                            {g}
                          </Badge>
                        ))}
                        {u.groups.length > 6 && (
                          <Tooltip label={u.groups.slice(6).join(', ')} multiline maw={300}>
                            <Badge size="sm" variant="light" color="gray">
                              +{u.groups.length - 6}
                            </Badge>
                          </Tooltip>
                        )}
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      {u.serviceAccount ? (
                        <Badge size="sm" variant="light" color="gray" radius="sm">
                          service account
                        </Badge>
                      ) : (
                        <Text size="xs" c="dimmed" ff="monospace" title={u.subject}>
                          {u.issuer}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed" title={formatDate(u.lastLoginAt)}>
                        {u.lastLoginAt ? formatRelative(u.lastLoginAt) : 'Never'}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
    </>
  );
}
