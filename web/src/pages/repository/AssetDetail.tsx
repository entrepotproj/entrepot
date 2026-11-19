import { Anchor, Badge, Button, Group, Skeleton, Stack, Text, Title, Tooltip } from '@mantine/core';
import {
  IconBrandGitlab,
  IconCloudDownload,
  IconDownload,
  IconExternalLink,
  IconGitBranch,
  IconGitCommit,
  IconPackage,
  IconTrash,
  IconUser,
} from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router';
import { api, unwrap, unwrapVoid, type Asset } from '../../api/client';
import { qk, useRepository } from '../../api/queries';
import { CopyText } from '../../components/CodeBlock';
import { ConfirmDelete } from '../../components/ConfirmDelete';
import { DetailList } from '../../components/DetailList';
import { JsonView } from '../../components/JsonView';
import { QueryError } from '../../components/states';
import { formatBytes, formatDate, formatRelative } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

export function useAsset(id: string | null) {
  return useQuery({
    queryKey: ['assets', id],
    queryFn: () => unwrap(api.GET('/assets/{id}', { params: { path: { id: id! } } })),
    enabled: !!id,
  });
}

type Uploader = { [key: string]: unknown };

function str(v: unknown): string {
  return v == null ? '' : String(v);
}

/** Who stored the asset; GitLab CI jobs show project, ref, commit, pipeline and job. */
function UploaderView({ uploader, fallback }: { uploader: Uploader; fallback: string }) {
  const kind = str(uploader.kind);
  const name = str(uploader.name) || fallback;
  const project = str(uploader.project_path ?? uploader.projectPath);
  const ref = str(uploader.ref);
  const sha = str(uploader.sha);
  const pipeline = str(uploader.pipeline_id ?? uploader.pipelineId);
  const job = str(uploader.job_id ?? uploader.jobId);
  const iss = str(uploader.iss).replace(/\/+$/, '');
  const gitlabBase = /^https?:\/\//.test(iss) ? iss : '';
  const instance = str(uploader.gitlab);
  const requestedBy = str(uploader.requestedBy);
  const userLogin = str(uploader.user_login);
  const projectUrl = gitlabBase && project ? `${gitlabBase}/${project}` : '';
  const isGitlab = kind === 'gitlab' || !!project;
  return (
    <Stack gap={4}>
      <Group gap={6} wrap="nowrap">
        <Badge
          size="sm"
          variant="light"
          color={isGitlab ? 'orange' : kind === 'bootstrap' ? 'grape' : kind === 'proxy' ? 'violet' : 'blue'}
          leftSection={
            isGitlab ? <IconBrandGitlab size={12} /> : kind === 'proxy' ? <IconCloudDownload size={12} /> : <IconUser size={12} />
          }
          tt="none"
          radius="sm"
        >
          {kind || 'user'}
        </Badge>
        <Text size="sm" fw={500}>
          {name}
        </Text>
        {instance && (
          <Text size="xs" c="dimmed">
            on {instance}
          </Text>
        )}
      </Group>
      {kind === 'proxy' && requestedBy && (
        <Text size="xs" c="dimmed">
          cached on request of {requestedBy}
        </Text>
      )}
      {isGitlab && (
        <Stack gap={2}>
          {project && (
            <Text size="xs">
              <Text span c="dimmed" size="xs">
                project{' '}
              </Text>
              {projectUrl ? (
                <Anchor href={projectUrl} target="_blank" rel="noreferrer" size="xs" ff="monospace">
                  {project}
                </Anchor>
              ) : (
                <Text span ff="monospace" size="xs">
                  {project}
                </Text>
              )}
            </Text>
          )}
          {(ref || sha) && (
            <Group gap={6}>
              {ref && (
                <Badge size="sm" variant="default" leftSection={<IconGitBranch size={12} />} tt="none" radius="sm">
                  {ref}
                </Badge>
              )}
              {sha && (
                <Tooltip label={sha} withArrow>
                  {projectUrl ? (
                    <Badge
                      component="a"
                      href={`${projectUrl}/-/commit/${sha}`}
                      target="_blank"
                      rel="noreferrer"
                      size="sm"
                      variant="default"
                      leftSection={<IconGitCommit size={12} />}
                      tt="none"
                      radius="sm"
                      ff="monospace"
                      style={{ cursor: 'pointer' }}
                    >
                      {sha.slice(0, 8)}
                    </Badge>
                  ) : (
                    <Badge size="sm" variant="default" leftSection={<IconGitCommit size={12} />} tt="none" radius="sm" ff="monospace">
                      {sha.slice(0, 8)}
                    </Badge>
                  )}
                </Tooltip>
              )}
            </Group>
          )}
          {(pipeline || job) && (
            <Text size="xs" c="dimmed">
              {pipeline && (
                <>
                  pipeline{' '}
                  {projectUrl ? (
                    <Anchor href={`${projectUrl}/-/pipelines/${pipeline}`} target="_blank" rel="noreferrer" size="xs">
                      #{pipeline}
                    </Anchor>
                  ) : (
                    <Text span size="xs" c="var(--mantine-color-text)">
                      #{pipeline}
                    </Text>
                  )}
                </>
              )}
              {pipeline && job && ' · '}
              {userLogin && (pipeline || job) && ' · '}
              {job && (
                <>
                  job{' '}
                  {projectUrl ? (
                    <Anchor href={`${projectUrl}/-/jobs/${job}`} target="_blank" rel="noreferrer" size="xs">
                      #{job}
                    </Anchor>
                  ) : (
                    <Text span size="xs" c="var(--mantine-color-text)">
                      #{job}
                    </Text>
                  )}
                </>
              )}
              {userLogin && <> triggered by {userLogin}</>}
            </Text>
          )}
        </Stack>
      )}
    </Stack>
  );
}

function When({ at }: { at?: string }) {
  if (!at) return <Text size="sm" c="dimmed">—</Text>;
  return (
    <Text size="sm" title={formatDate(at)}>
      {formatDate(at)}{' '}
      <Text span size="xs" c="dimmed">
        ({formatRelative(at)})
      </Text>
    </Text>
  );
}

/** Asset metadata, download and delete. Used in the browse drawer and on /assets/:id. */
export function AssetDetail({
  id,
  onDeleted,
  showOpenLink,
}: {
  id: string;
  onDeleted?: (a: Asset) => void;
  showOpenLink?: boolean;
}) {
  const { data: a, isPending, error, refetch } = useAsset(id);
  const repo = useRepository(a?.repository ?? '');
  const canDelete = !!repo.data?.permissions.includes('delete');
  const [confirm, setConfirm] = useState(false);
  const qc = useQueryClient();

  const del = useMutation({
    mutationFn: () => unwrapVoid(api.DELETE('/assets/{id}', { params: { path: { id } } })),
    onSuccess: () => {
      setConfirm(false);
      if (a) onDeleted?.(a);
      notifySuccess(`Deleted ${a?.path}`);
      qc.invalidateQueries({ queryKey: ['browse', a?.repository] });
      qc.invalidateQueries({ queryKey: ['components'] });
      qc.invalidateQueries({ queryKey: qk.repository(a?.repository ?? '') });
      qc.removeQueries({ queryKey: ['assets', id], exact: true });
    },
  });

  if (error) return <QueryError error={error} retry={refetch} />;
  if (isPending || !a) {
    return (
      <Stack>
        <Skeleton height={24} width="60%" />
        <Skeleton height={200} />
      </Stack>
    );
  }

  return (
    <Stack gap="lg">
      <div>
        <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
          Asset
        </Text>
        <Title order={4} style={{ wordBreak: 'break-all' }} ff="monospace" fw={600}>
          {a.path}
        </Title>
      </div>
      <Group gap="xs">
        {a.downloadUrl && (
          <Button component="a" href={a.downloadUrl} leftSection={<IconDownload size={16} />} size="sm">
            Download
          </Button>
        )}
        {showOpenLink && (
          <Button
            component={Link}
            to={`/assets/${a.id}`}
            variant="default"
            size="sm"
            leftSection={<IconExternalLink size={16} />}
          >
            Open page
          </Button>
        )}
        {canDelete && (
          <Button color="red" variant="light" size="sm" leftSection={<IconTrash size={16} />} onClick={() => setConfirm(true)}>
            Delete
          </Button>
        )}
      </Group>
      <DetailList
        items={[
          [
            'Repository',
            <Anchor component={Link} to={`/repositories/${a.repository}`} size="sm">
              {a.repository}
            </Anchor>,
          ],
          [
            'Size',
            <Text size="sm">
              {formatBytes(a.size)}{' '}
              <Text span size="xs" c="dimmed">
                ({a.size.toLocaleString()} bytes)
              </Text>
            </Text>,
          ],
          ['Digest', <CopyText value={a.digest} />],
          ['Content type', <Badge variant="default" tt="none" radius="sm" fw={500}>{a.contentType || 'unknown'}</Badge>],
          ['Created by', a.uploader && Object.keys(a.uploader).length > 0 ? <UploaderView uploader={a.uploader} fallback={a.createdBy} /> : a.createdBy || '—'],
          ['Created', <When at={a.createdAt} />],
          ['Updated', <When at={a.updatedAt} />],
          ['Cached', <When at={a.cachedAt} />],
          ['Last downloaded', <When at={a.lastDownloadedAt} />],
          ...(a.componentId
            ? ([
                [
                  'Component',
                  <Anchor component={Link} to={`/components/${a.componentId}`} size="sm">
                    <Group gap={4} wrap="nowrap">
                      <IconPackage size={14} /> View component
                    </Group>
                  </Anchor>,
                ],
              ] as [string, React.ReactNode][])
            : []),
        ]}
      />
      <div>
        <Text size="sm" fw={600} mb={6}>
          Attributes
        </Text>
        <JsonView value={a.attrs} />
      </div>
      <ConfirmDelete
        opened={confirm}
        onClose={() => setConfirm(false)}
        onConfirm={() => del.mutate()}
        loading={del.isPending}
        title="Delete asset"
      >
        Permanently delete <b>{a.path}</b> from {a.repository}? This cannot be undone.
      </ConfirmDelete>
    </Stack>
  );
}
