import { Button, Group, Paper, Text, Title } from '@mantine/core';
import { IconTrash } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { api, unwrap, unwrapVoid, type Repository, type RepositoryInput } from '../../api/client';
import { qk } from '../../api/queries';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { notifySuccess } from '../../lib/notify';
import { RepositoryForm } from './RepositoryForm';

export function SettingsTab({ repository }: { repository: Repository }) {
  const name = repository.name;
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState(false);

  const save = useMutation({
    mutationFn: (body: RepositoryInput) => unwrap(api.PUT('/repositories/{name}', { params: { path: { name } }, body })),
    onSuccess: (r) => {
      qc.setQueryData(qk.repository(name), r);
      qc.invalidateQueries({ queryKey: qk.repositories });
      notifySuccess('Settings saved');
    },
  });

  const del = useMutation({
    mutationFn: () => unwrapVoid(api.DELETE('/repositories/{name}', { params: { path: { name } } })),
    onSuccess: () => {
      setConfirm(false);
      navigate('/repositories');
      qc.removeQueries({ queryKey: qk.repository(name), exact: true });
      qc.invalidateQueries({ queryKey: qk.repositories });
      notifySuccess(`Repository ${name} deleted`);
    },
  });

  return (
    <>
      <RepositoryForm
        key={repository.updatedAt}
        repository={repository}
        onSubmit={(b) => save.mutate(b)}
        submitting={save.isPending}
        submitLabel="Save changes"
      />
      <Paper p="lg" mt="xl" style={{ borderColor: 'var(--mantine-color-red-light-color)' }}>
        <Group justify="space-between" wrap="wrap">
          <div>
            <Title order={5} c="red">
              Delete repository
            </Title>
            <Text size="sm" c="dimmed">
              Deletes the repository and all of its content. This cannot be undone.
            </Text>
          </div>
          <Button color="red" variant="light" leftSection={<IconTrash size={16} />} onClick={() => setConfirm(true)}>
            Delete repository
          </Button>
        </Group>
      </Paper>
      <ConfirmDelete
        opened={confirm}
        onClose={() => setConfirm(false)}
        onConfirm={() => del.mutate()}
        loading={del.isPending}
        title={`Delete ${name}`}
        confirmText={name}
        confirmLabel="Delete repository"
      >
        All assets and components in <b>{name}</b> will be permanently deleted. Group repositories that include it
        must be updated separately.
      </ConfirmDelete>
    </>
  );
}
