import { Button, Group, Modal, Stack, Text, TextInput } from '@mantine/core';
import { IconTrash } from '@tabler/icons-react';
import { useEffect, useState, type ReactNode } from 'react';

/**
 * Deletion confirmation. With `confirmText`, the user must type it (e.g. the
 * repository name) before the delete button is enabled.
 */
export function ConfirmDelete({
  opened,
  onClose,
  onConfirm,
  title,
  children,
  confirmText,
  loading,
  confirmLabel = 'Delete',
}: {
  opened: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  children?: ReactNode;
  confirmText?: string;
  loading?: boolean;
  confirmLabel?: string;
}) {
  const [typed, setTyped] = useState('');
  useEffect(() => {
    if (opened) setTyped('');
  }, [opened]);
  const ok = !confirmText || typed === confirmText;
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>{title}</Text>} centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) onConfirm();
        }}
      >
        <Stack>
          {children && <Text size="sm">{children}</Text>}
          {confirmText && (
            <TextInput
              label={
                <>
                  Type <b>{confirmText}</b> to confirm
                </>
              }
              value={typed}
              onChange={(e) => setTyped(e.currentTarget.value)}
              autoFocus
              data-autofocus
              autoComplete="off"
            />
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button color="red" type="submit" disabled={!ok} loading={loading} leftSection={<IconTrash size={16} />}>
              {confirmLabel}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
