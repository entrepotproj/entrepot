import { Button, Chip, Code, Group, Modal, SimpleGrid, Stack, Text, Textarea, TextInput } from '@mantine/core';
import { IconShieldOff } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, unwrap, type Waiver, type WaiverInput } from '../api/client';
import { qk2 } from '../api/queries';
import { notifySuccess } from '../lib/notify';

function toDateInput(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function inDays(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return toDateInput(d.toISOString());
}

const PRESETS: { label: string; days: number }[] = [
  { label: '30 days', days: 30 },
  { label: '90 days', days: 90 },
  { label: '1 year', days: 365 },
];

/** Create or edit a waiver (vulnerabilities and file scanner threats). `initial` prefills a new waiver. */
export function WaiverModal({
  waiver,
  initial,
  onClose,
  onSaved,
}: {
  waiver?: Waiver | null;
  initial?: Partial<WaiverInput>;
  onClose: () => void;
  onSaved?: (w: Waiver) => void;
}) {
  const editing = !!waiver;
  const qc = useQueryClient();
  const src = waiver ?? initial ?? {};
  const [vulnId, setVulnId] = useState(src.vulnId ?? '');
  const [repositoryPattern, setRepositoryPattern] = useState(src.repositoryPattern ?? '*');
  const [componentPattern, setComponentPattern] = useState(src.componentPattern ?? '*');
  const [reason, setReason] = useState(src.reason ?? '');
  const [expires, setExpires] = useState(editing ? toDateInput(waiver?.expiresAt) : initial ? inDays(90) : '');

  const save = useMutation({
    mutationFn: (body: WaiverInput) =>
      editing
        ? unwrap(api.PUT('/waivers/{id}', { params: { path: { id: waiver!.id } }, body }))
        : unwrap(api.POST('/waivers', { body })),
    onSuccess: (w) => {
      qc.invalidateQueries({ queryKey: qk2.waivers });
      qc.invalidateQueries({ queryKey: ['component-scans'] });
      notifySuccess(`Waiver for ${w.vulnId} saved`);
      onSaved?.(w);
      onClose();
    },
  });

  const valid = !!vulnId.trim() && !!repositoryPattern.trim() && !!componentPattern.trim();
  const past = !!expires && new Date(expires + 'T23:59:59') < new Date();

  return (
    <Modal
      opened
      onClose={onClose}
      title={<Text fw={600}>{editing ? 'Edit waiver' : 'Waive vulnerability'}</Text>}
      size="lg"
      centered
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!valid) return;
          save.mutate({
            vulnId: vulnId.trim(),
            repositoryPattern: repositoryPattern.trim(),
            componentPattern: componentPattern.trim(),
            reason: reason.trim(),
            expiresAt: expires ? new Date(expires + 'T23:59:59').toISOString() : undefined,
          });
        }}
      >
        <Stack>
          <Text size="sm" c="dimmed">
            Waived findings are still reported but no longer mark a component vulnerable or quarantine it. Patterns are
            globs: <Code>*</Code> matches anything.
          </Text>
          <TextInput
            label="Finding ID"
            description={
              <>
                e.g. CVE-2021-23337, GHSA-…, <Code fz={11}>MALWARE:…</Code>, or * for any vulnerability (never covers
                malware and policy blocks, which need their exact ID)
              </>
            }
            value={vulnId}
            onChange={(e) => setVulnId(e.currentTarget.value)}
            required
            data-autofocus
            styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
          />
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <TextInput
              label="Repository pattern"
              description="Repository names, e.g. npm-* "
              value={repositoryPattern}
              onChange={(e) => setRepositoryPattern(e.currentTarget.value)}
              required
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
            <TextInput
              label="Component pattern"
              description={'"name" or "name@version", e.g. lodash@4.*'}
              value={componentPattern}
              onChange={(e) => setComponentPattern(e.currentTarget.value)}
              required
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
          </SimpleGrid>
          <Textarea
            label="Reason"
            description="Why is this acceptable? Shown to everyone who sees the finding."
            placeholder="Not exploitable: the vulnerable function is never called."
            autosize
            minRows={2}
            value={reason}
            onChange={(e) => setReason(e.currentTarget.value)}
          />
          <div>
            <Group align="flex-end" gap="sm" wrap="wrap">
              <TextInput
                type="date"
                label="Expires"
                description="Leave empty for no expiry"
                value={expires}
                onChange={(e) => setExpires(e.currentTarget.value)}
                w={200}
                error={past ? 'In the past' : null}
              />
              <Chip.Group>
                <Group gap={6} pb={4}>
                  {PRESETS.map((p) => (
                    <Chip
                      key={p.label}
                      size="xs"
                      variant="outline"
                      checked={expires === inDays(p.days)}
                      onChange={() => setExpires(inDays(p.days))}
                    >
                      {p.label}
                    </Chip>
                  ))}
                  <Chip size="xs" variant="outline" checked={!expires} onChange={() => setExpires('')}>
                    Never
                  </Chip>
                </Group>
              </Chip.Group>
            </Group>
          </div>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!valid} loading={save.isPending} leftSection={<IconShieldOff size={16} />}>
              {editing ? 'Save waiver' : 'Create waiver'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
