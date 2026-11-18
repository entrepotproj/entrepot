import { Alert, Anchor } from '@mantine/core';
import { IconInfoCircle } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from 'react-router';
import { api, unwrap, type RepositoryInput } from '../api/client';
import { qk, useBlobStores } from '../api/queries';
import { PageHeader } from '../components/PageHeader';
import { notifySuccess } from '../lib/notify';
import { RepositoryForm } from './repository/RepositoryForm';

export function RepositoryCreatePage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const blobStores = useBlobStores();
  const create = useMutation({
    mutationFn: (body: RepositoryInput) => unwrap(api.POST('/repositories', { body })),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: qk.repositories });
      notifySuccess(`Repository ${r.name} created`);
      navigate(`/repositories/${r.name}`);
    },
  });

  return (
    <>
      <PageHeader
        title="Create repository"
        crumbs={[{ label: 'Repositories', to: '/repositories' }, { label: 'New' }]}
      />
      {blobStores.data && blobStores.data.length === 0 && (
        <Alert color="orange" variant="light" icon={<IconInfoCircle size={18} />} mb="md" title="No blob stores">
          Repositories store their content in a blob store.{' '}
          <Anchor component={Link} to="/admin/blob-stores">
            Create a blob store
          </Anchor>{' '}
          first.
        </Alert>
      )}
      <RepositoryForm onSubmit={(b) => create.mutate(b)} submitting={create.isPending} submitLabel="Create repository" />
    </>
  );
}
