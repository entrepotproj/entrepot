import { ActionIcon, Badge, Button, Group, Paper, SegmentedControl, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { IconPencil, IconPlus, IconSearch, IconShieldOff, IconTrash } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { api, isNotImplemented, unwrapVoid, type Waiver } from '../../api/client';
import { qk2, useWaivers } from '../../api/queries';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { PageHeader } from '../../components/PageHeader';
import { EmptyState, QueryError, TableSkeleton } from '../../components/states';
import { WaiverModal } from '../../components/WaiverModal';
import { formatDate, formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

function expired(w: Waiver) {
  return !!w.expiresAt && new Date(w.expiresAt).getTime() < Date.now();
}

function ExpiryCell({ w }: { w: Waiver }) {
  if (!w.expiresAt) {
    return (
      <Text size="sm" c="dimmed">
        never
      </Text>
    );
  }
  if (expired(w)) {
    return (
      <Tooltip label={`Expired ${formatDate(w.expiresAt)}`} withArrow>
        <Badge variant="light" color="gray" tt="none" radius="sm">
          expired {formatRelative(w.expiresAt)}
        </Badge>
      </Tooltip>
    );
  }
  const soon = new Date(w.expiresAt).getTime() - Date.now() < 14 * 86400_000;
  return (
    <Text size="sm" c={soon ? 'orange' : undefined} title={formatDate(w.expiresAt)}>
      {formatRelative(w.expiresAt)}
    </Text>
  );
}

export default function WaiversPage() {
  const { data, isPending, error, refetch } = useWaivers();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Waiver | 'new' | null>(null);
  const [deleting, setDeleting] = useState<Waiver | null>(null);
  const [q, setQ] = useState('');
  const [show, setShow] = useState<'active' | 'expired' | 'all'>('all');

  const del = useMutation({
    mutationFn: (id: string) => unwrapVoid(api.DELETE('/waivers/{id}', { params: { path: { id } } })),
    onSuccess: () => {
      notifySuccess(`Waiver for ${deleting?.vulnId} deleted`);
      setDeleting(null);
      qc.invalidateQueries({ queryKey: qk2.waivers });
      qc.invalidateQueries({ queryKey: ['component-scans'] });
    },
  });

  const rows = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (data ?? [])
      .filter((w) => show === 'all' || (show === 'expired') === expired(w))
      .filter(
        (w) =>
          !s ||
          [w.vulnId, w.repositoryPattern, w.componentPattern, w.reason, w.createdBy].some((x) => x.toLowerCase().includes(s)),
      )
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }, [data, q, show]);

  return (
    <>
      <PageHeader
        title="Waivers"
        description="Accepted vulnerabilities. Waived findings are still shown but do not mark components vulnerable or quarantine them."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setEditing('new')} disabled={isNotImplemented(error)}>
            Create waiver
          </Button>
        }
      />
      <Paper p={0}>
        {data && data.length > 0 && (
          <Group p="sm" justify="space-between" wrap="wrap">
            <SegmentedControl
              size="xs"
              value={show}
              onChange={(v) => setShow(v as typeof show)}
              data={[
                { value: 'all', label: `All (${data.length})` },
                { value: 'active', label: 'Active' },
                { value: 'expired', label: `Expired (${data.filter(expired).length})` },
              ]}
            />
            <TextInput
              size="xs"
              w={260}
              placeholder="Filter by CVE, pattern, reason"
              leftSection={<IconSearch size={14} />}
              value={q}
              onChange={(e) => setQ(e.currentTarget.value)}
            />
          </Group>
        )}
        {error ? (
          <div style={{ padding: 12 }}>
            <QueryError error={error} retry={refetch} feature="Vulnerability waivers" />
          </div>
        ) : isPending ? (
          <TableSkeleton rows={4} cols={5} />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<IconShieldOff size={28} stroke={1.5} />}
            title={data.length ? 'No matching waivers' : 'No waivers'}
            description={
              data.length
                ? 'Try a different filter.'
                : 'Waive a finding from a component page, or create a waiver here for a vulnerability that does not affect you.'
            }
          />
        ) : (
          <Table.ScrollContainer minWidth={820}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Vulnerability</Table.Th>
                  <Table.Th>Repositories</Table.Th>
                  <Table.Th>Components</Table.Th>
                  <Table.Th>Reason</Table.Th>
                  <Table.Th>Created</Table.Th>
                  <Table.Th>Expires</Table.Th>
                  <Table.Th w={80} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rows.map((w) => (
                  <Table.Tr key={w.id} style={expired(w) ? { opacity: 0.6 } : undefined}>
                    <Table.Td>
                      <Text size="sm" ff="monospace" fw={600}>
                        {w.vulnId === '*' ? '* (any)' : w.vulnId}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace">
                        {w.repositoryPattern}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace" style={{ wordBreak: 'break-all' }}>
                        {w.componentPattern}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" lineClamp={2} maw={320} title={w.reason} c={w.reason ? undefined : 'dimmed'}>
                        {w.reason || '—'}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" title={formatDate(w.createdAt)}>
                        {formatRelative(w.createdAt)}
                      </Text>
                      <Text size="xs" c="dimmed">
                        by {w.createdBy}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <ExpiryCell w={w} />
                    </Table.Td>
                    <Table.Td>
                      <Group gap={2} wrap="nowrap">
                        <Tooltip label="Edit">
                          <ActionIcon variant="subtle" color="gray" onClick={() => setEditing(w)} aria-label="Edit">
                            <IconPencil size={16} />
                          </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Delete">
                          <ActionIcon variant="subtle" color="red" onClick={() => setDeleting(w)} aria-label="Delete">
                            <IconTrash size={16} />
                          </ActionIcon>
                        </Tooltip>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      {editing && <WaiverModal waiver={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      <ConfirmDelete
        opened={!!deleting}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && del.mutate(deleting.id)}
        loading={del.isPending}
        title="Delete waiver"
      >
        Delete the waiver for <b>{deleting?.vulnId}</b> on <code>{deleting?.repositoryPattern}</code> /{' '}
        <code>{deleting?.componentPattern}</code>? Matching findings count again, which can quarantine components.
      </ConfirmDelete>
    </>
  );
}
