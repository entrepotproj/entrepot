import { Alert, Anchor, Box, Button, Group, Paper, Select, SimpleGrid, Stack, Text, TextInput, Title } from '@mantine/core';
import { IconCircleCheck, IconFileUpload, IconUpload } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { Link } from 'react-router';
import { api, unwrap, type Asset, type Repository } from '../../api/client';
import { qk } from '../../api/queries';
import { formatBytes } from '../../lib/format';
import { notifySuccess } from '../../lib/notify';

const hints: Record<string, { accept: string; help: string }> = {
  raw: { accept: '', help: 'Any file. Choose the destination path inside the repository.' },
  pypi: { accept: '.whl,.tar.gz,.zip', help: 'A wheel (.whl) or source distribution (.tar.gz). Name and version are read from the file name.' },
  npm: { accept: '.tgz', help: 'A package tarball created with npm pack. package.json is read from the tarball.' },
  apt: {
    accept: '.deb',
    help: 'A Debian package (.deb). It is added to the chosen distribution and component, and the signed indexes are regenerated.',
  },
  yum: { accept: '.rpm', help: 'An RPM package. Choose the directory; repodata is regenerated and signed.' },
  helm: { accept: '.tgz', help: 'A packaged chart (helm package). Chart.yaml is read from the archive and index.yaml is updated.' },
};

export function UploadTab({ repository }: { repository: Repository }) {
  const name = repository.name;
  const hint = hints[repository.format] ?? hints.raw;
  const [file, setFile] = useState<File | null>(null);
  const [path, setPath] = useState('');
  const [dragging, setDragging] = useState(false);
  const [result, setResult] = useState<Asset[] | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const qc = useQueryClient();
  const raw = repository.format === 'raw';
  const yum = repository.format === 'yum';
  const depth = repository.hosted?.yum?.repodataDepth ?? 0;
  const [dir, setDir] = useState(['el9', 'x86_64', 'extras', 'a', 'b'].slice(0, depth).join('/'));
  const apt = repository.format === 'apt';
  const dists = repository.hosted?.apt?.distributions?.length
    ? repository.hosted.apt.distributions
    : [{ name: 'stable', components: ['main'] }];
  const [dist, setDist] = useState(dists[0].name);
  const comps = dists.find((d) => d.name === dist)?.components?.length ? dists.find((d) => d.name === dist)!.components! : ['main'];
  const [component, setComponent] = useState(comps[0]);

  const choose = (f: File | null) => {
    setFile(f);
    setResult(null);
    if (f && raw) {
      const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : '';
      setPath(dir + f.name);
    }
  };

  const upload = useMutation({
    mutationFn: (f: File) =>
      unwrap(
        api.POST('/repositories/{name}/upload', {
          params: { path: { name } },
          body: { file: '', path: raw && path.trim() ? path.trim() : yum && dir.trim() ? dir.trim() : undefined },
          bodySerializer: (b) => {
            const fd = new FormData();
            fd.append('file', f, f.name);
            if (b.path) fd.append('path', b.path);
            if (apt) {
              fd.append('distribution', dist);
              fd.append('component', component);
            }
            return fd;
          },
        }),
      ),
    onSuccess: (assets) => {
      setResult(assets);
      setFile(null);
      if (input.current) input.current.value = '';
      notifySuccess(`Uploaded ${assets.length === 1 ? assets[0].path : `${assets.length} assets`}`);
      qc.invalidateQueries({ queryKey: ['browse', name] });
      qc.invalidateQueries({ queryKey: ['components', name] });
      qc.invalidateQueries({ queryKey: qk.repository(name) });
    },
  });

  return (
    <Paper p="lg">
      <Title order={5}>Upload</Title>
      <Text size="sm" c="dimmed" mb="md">
        {hint.help}
      </Text>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (file) upload.mutate(file);
        }}
      >
        <Stack>
          <Box
            onClick={() => input.current?.click()}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              choose(e.dataTransfer.files?.[0] ?? null);
            }}
            style={{
              cursor: 'pointer',
              border: `2px dashed ${dragging ? 'var(--mantine-primary-color-filled)' : 'var(--mantine-color-default-border)'}`,
              borderRadius: 'var(--mantine-radius-md)',
              background: dragging ? 'var(--mantine-primary-color-light)' : undefined,
              padding: '28px 16px',
              textAlign: 'center',
            }}
          >
            <IconFileUpload size={34} stroke={1.4} color="var(--mantine-color-dimmed)" />
            {file ? (
              <Text size="sm" fw={500} mt={6}>
                {file.name}{' '}
                <Text span c="dimmed" size="sm">
                  ({formatBytes(file.size)})
                </Text>
              </Text>
            ) : (
              <Text size="sm" mt={6}>
                Drop a file here or <Anchor component="span">browse</Anchor>
              </Text>
            )}
            <input
              ref={input}
              type="file"
              hidden
              accept={hint.accept || undefined}
              onChange={(e) => choose(e.currentTarget.files?.[0] ?? null)}
            />
          </Box>
          {apt && (
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <Select
                label="Distribution"
                data={dists.map((d) => d.name)}
                value={dist}
                onChange={(v) => {
                  if (!v) return;
                  setDist(v);
                  const c = dists.find((d) => d.name === v)?.components ?? [];
                  setComponent(c[0] ?? 'main');
                }}
                allowDeselect={false}
              />
              <Select
                label="Component"
                data={comps}
                value={comps.includes(component) ? component : comps[0]}
                onChange={(v) => v && setComponent(v)}
                allowDeselect={false}
              />
            </SimpleGrid>
          )}
          {yum && (
            <TextInput
              label="Directory"
              description={
                depth > 0
                  ? `Repodata is generated ${depth} director${depth === 1 ? 'y' : 'ies'} deep, so packages must be in a directory like this.`
                  : 'Optional sub-directory; repodata is generated at the repository root.'
              }
              placeholder={depth > 0 ? 'el9/x86_64' : ''}
              value={dir}
              onChange={(e) => setDir(e.currentTarget.value)}
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
          )}
          {raw && (
            <TextInput
              label="Destination path"
              description="Path inside the repository, e.g. releases/1.0/app.tar.gz. Defaults to the file name."
              placeholder="dir/file.txt"
              value={path}
              onChange={(e) => setPath(e.currentTarget.value)}
            />
          )}
          <Group justify="flex-end">
            <Button type="submit" leftSection={<IconUpload size={16} />} disabled={!file} loading={upload.isPending}>
              Upload
            </Button>
          </Group>
          {result && (
            <Alert color="teal" variant="light" icon={<IconCircleCheck size={18} />} title="Upload complete">
              <Stack gap={2}>
                {result.map((a) => (
                  <Anchor key={a.id} component={Link} to={`/assets/${a.id}`} size="sm" ff="monospace">
                    {a.path} ({formatBytes(a.size)})
                  </Anchor>
                ))}
              </Stack>
            </Alert>
          )}
        </Stack>
      </form>
    </Paper>
  );
}
