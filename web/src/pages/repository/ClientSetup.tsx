import { Alert, Anchor, Group, Paper, SegmentedControl, Stack, Text, Title } from '@mantine/core';
import { IconBrandGitlab, IconInfoCircle, IconTerminal2 } from '@tabler/icons-react';
import { useState } from 'react';
import { Link } from 'react-router';
import type { Repository } from '../../api/client';
import { useSystemInfo } from '../../api/queries';
import { CodeBlock } from '../../components/CodeBlock';

type Snippet = { title: string; code: string };

/** Splits a client URL into host and path ("http://h:1/repository/x/" -> "h:1", "/repository/x/"). */
function hostPath(url: string): { host: string; path: string } {
  try {
    const u = new URL(url);
    return { host: u.host, path: u.pathname };
  } catch {
    // docker URLs are host/repo without a scheme
    const i = url.indexOf('/');
    return i < 0 ? { host: url, path: '/' } : { host: url.slice(0, i), path: url.slice(i) };
  }
}

function ciJob(name: string, image: string, aud: string, script: string[], extra = ''): string {
  return [
    `${name}:`,
    `  image: ${image}`,
    extra,
    `  id_tokens:`,
    `    ENTREPOT_ID_TOKEN:`,
    `      aud: ${aud}`,
    `  script:`,
    ...script.map((l) => `    - ${l}`),
  ]
    .filter(Boolean)
    .join('\n');
}

function snippets(r: Repository, baseUrl: string): { cli: Snippet[]; ci: Snippet[] } {
  const url = r.url;
  const hosted = r.kind === 'hosted';
  const auth = !r.anonymousRead;
  const { host, path } = hostPath(url);
  const scheme = url.startsWith('https://') ? 'https://' : 'http://';

  switch (r.format) {
    case 'pypi': {
      const simple = `${url}simple/`;
      const authed = `${scheme}token:<TOKEN>@${host}${path}simple/`;
      const cli: Snippet[] = [
        { title: 'Install a package', code: `pip install --index-url ${auth ? authed : simple} <package>` },
        {
          title: 'pip.conf (~/.config/pip/pip.conf)',
          code: `[global]\nindex-url = ${auth ? authed : simple}`,
        },
      ];
      if (hosted) {
        cli.push({ title: 'Publish with twine', code: `twine upload --repository-url ${url} -u token -p <TOKEN> dist/*` });
      }
      const ci: Snippet[] = [
        {
          title: '.gitlab-ci.yml',
          code: hosted
            ? ciJob('publish', 'python:3.12', baseUrl, [
                'pip install build twine',
                'python -m build',
                `twine upload --repository-url ${url} -u gitlab-ci -p "$ENTREPOT_ID_TOKEN" dist/*`,
              ])
            : ciJob('test', 'python:3.12', baseUrl, [
                `pip install --index-url "${scheme}gitlab-ci:$ENTREPOT_ID_TOKEN@${host}${path}simple/" -r requirements.txt`,
              ]),
        },
      ];
      return { cli, ci };
    }
    case 'npm': {
      const cli: Snippet[] = [
        {
          title: '.npmrc',
          code: `registry=${url}\n//${host}${path}:_authToken=<TOKEN>`,
        },
        { title: 'Install', code: `npm install --registry ${url} <package>` },
      ];
      if (hosted) cli.push({ title: 'Publish', code: `npm publish --registry ${url}` });
      const ci: Snippet[] = [
        {
          title: '.gitlab-ci.yml',
          code: ciJob(hosted ? 'publish' : 'build', 'node:22', baseUrl, [
            `npm config set registry ${url}`,
            `npm config set //${host}${path}:_authToken "$ENTREPOT_ID_TOKEN"`,
            hosted ? 'npm publish' : 'npm ci',
          ]),
        },
      ];
      return { cli, ci };
    }
    case 'docker': {
      // The docker client URL is "host/repo"; tolerate an http(s) URL too.
      const ref = /^https?:\/\//.test(url) ? `${host}/${r.name}` : url.replace(/\/+$/, '');
      const reg = ref.split('/')[0];
      const cli: Snippet[] = [
        { title: 'Log in (username: anything, password: an API token)', code: `docker login ${reg}` },
        { title: 'Pull an image', code: `docker pull ${ref}/<image>:<tag>` },
      ];
      if (hosted) {
        cli.push({
          title: 'Push an image',
          code: `docker tag <image>:<tag> ${ref}/<image>:<tag>\ndocker push ${ref}/<image>:<tag>`,
        });
      }
      const ci: Snippet[] = [
        {
          title: '.gitlab-ci.yml',
          code: ciJob(
            hosted ? 'build-image' : 'pull-image',
            'docker:27',
            baseUrl,
            [
              `echo "$ENTREPOT_ID_TOKEN" | docker login ${reg} -u gitlab-ci --password-stdin`,
              ...(hosted
                ? [
                    `docker build -t ${ref}/$CI_PROJECT_NAME:$CI_COMMIT_SHORT_SHA .`,
                    `docker push ${ref}/$CI_PROJECT_NAME:$CI_COMMIT_SHORT_SHA`,
                  ]
                : [`docker pull ${ref}/<image>:<tag>`]),
            ],
            '  services: [docker:27-dind]',
          ),
        },
      ];
      return { cli, ci };
    }
    default: {
      const authFlag = auth ? '-u token:<TOKEN> ' : '';
      const cli: Snippet[] = [{ title: 'Download a file', code: `curl -fL ${authFlag}-O ${url}path/to/file.tar.gz` }];
      if (hosted) {
        cli.unshift({
          title: 'Upload a file',
          code: `curl -f -u token:<TOKEN> --upload-file ./file.tar.gz ${url}path/to/file.tar.gz`,
        });
      }
      const ci: Snippet[] = [
        {
          title: '.gitlab-ci.yml',
          code: hosted
            ? ciJob('upload', 'curlimages/curl:latest', baseUrl, [
                `'curl -f -H "Authorization: Bearer $ENTREPOT_ID_TOKEN" --upload-file dist/app.tar.gz "${url}$CI_PROJECT_PATH/$CI_COMMIT_SHORT_SHA/app.tar.gz"'`,
              ])
            : ciJob('download', 'curlimages/curl:latest', baseUrl, [
                `'curl -fL -H "Authorization: Bearer $ENTREPOT_ID_TOKEN" -O "${url}path/to/file.tar.gz"'`,
              ]),
        },
      ];
      return { cli, ci };
    }
  }
}

export function ClientSetup({ repository }: { repository: Repository }) {
  const { data: info } = useSystemInfo();
  const [mode, setMode] = useState<'cli' | 'ci'>('cli');
  const baseUrl = (info?.baseUrl || window.location.origin).replace(/\/+$/, '');
  const s = snippets(repository, baseUrl);
  const list = mode === 'cli' ? s.cli : s.ci;

  return (
    <Paper p="lg" h="100%">
      <Group justify="space-between" mb="md" wrap="wrap">
        <div>
          <Title order={5}>Set up client</Title>
          <Text size="sm" c="dimmed">
            Point your tools at this repository.
          </Text>
        </div>
        <SegmentedControl
          size="xs"
          value={mode}
          onChange={(v) => setMode(v as 'cli' | 'ci')}
          data={[
            {
              value: 'cli',
              label: (
                <Group gap={6} wrap="nowrap">
                  <IconTerminal2 size={14} /> Local
                </Group>
              ),
            },
            {
              value: 'ci',
              label: (
                <Group gap={6} wrap="nowrap">
                  <IconBrandGitlab size={14} /> GitLab CI
                </Group>
              ),
            },
          ]}
        />
      </Group>
      <Stack gap="md">
        {list.map((sn) => (
          <CodeBlock key={sn.title} title={sn.title} code={sn.code} />
        ))}
        {mode === 'cli' && repository.format === 'docker' ? (
          <Text size="xs" c="dimmed">
            Log in with any username and an{' '}
            <Anchor component={Link} to="/tokens" size="xs">
              API token
            </Anchor>{' '}
            as the password.
          </Text>
        ) : mode === 'cli' ? (
          <Text size="xs" c="dimmed">
            Replace <code>&lt;TOKEN&gt;</code> with an{' '}
            <Anchor component={Link} to="/tokens" size="xs">
              API token
            </Anchor>
            {repository.anonymousRead ? '; reading works without one.' : '.'}
          </Text>
        ) : (
          <Alert variant="light" color="blue" icon={<IconInfoCircle size={18} />} p="sm">
            <Text size="xs">
              The job authenticates with a GitLab <code>id_token</code> whose audience is <code>{baseUrl}</code>. An
              administrator must create a GitLab trust policy matching your project and bind it to a role on this
              repository{repository.kind === 'hosted' ? ' that allows write' : ''}.
            </Text>
          </Alert>
        )}
      </Stack>
    </Paper>
  );
}
