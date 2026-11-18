import { Paper } from '@mantine/core';
import { useNavigate, useParams } from 'react-router';
import { PageHeader } from '../components/PageHeader';
import { AssetDetail, useAsset } from './repository/AssetDetail';

export function AssetPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const { data: a } = useAsset(id);
  return (
    <>
      <PageHeader
        title="Asset"
        crumbs={[
          { label: 'Repositories', to: '/repositories' },
          ...(a ? [{ label: a.repository, to: `/repositories/${a.repository}` }] : []),
          { label: a?.path.split('/').pop() ?? '…' },
        ]}
      />
      <Paper p="lg" maw={900}>
        <AssetDetail id={id} onDeleted={(x) => navigate(`/repositories/${x.repository}`)} />
      </Paper>
    </>
  );
}
