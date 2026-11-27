import { Alert, Anchor, Group, Paper, SegmentedControl, Stack, Text, Title } from '@mantine/core';
import { IconBrandGitlab, IconInfoCircle, IconTerminal2 } from '@tabler/icons-react';
import { useState } from 'react';
import { Link } from 'react-router';
import type { Repository } from '../../api/client';
import { useSigningKey, useSystemInfo } from '../../api/queries';
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

/** A sample upload directory for a Yum repository whose repodata is generated at the given depth. */
function yumDir(depth: number): string {
  const parts = ['el9', 'x86_64', 'extras', 'a', 'b'];
  return parts.slice(0, Math.max(0, Math.min(depth, 5))).map((p) => p + '/').join('');
}

function aptSnippets(r: Repository, baseUrl: string): { cli: Snippet[]; ci: Snippet[] } {
  const url = r.url;
  const hosted = r.kind === 'hosted';
  const auth = !r.anonymousRead;
  const { host, path } = hostPath(url);
  const dist = r.hosted?.apt?.distributions?.[0];
  const suite = hosted ? (dist?.name ?? 'stable') : 'bookworm';
  const comp = hosted ? (dist?.components?.[0] ?? 'main') : 'main';
  const keyring = hosted ? `/etc/apt/keyrings/entrepot-${r.name}.gpg` : '/usr/share/keyrings/debian-archive-keyring.gpg';
  const curlAuth = auth ? '-u x:<TOKEN> ' : '';
  const cli: Snippet[] = [];
  if (hosted) {
    cli.push({
      title: 'Trust the repository signing key',
      code: `sudo install -d -m 0755 /etc/apt/keyrings\nsudo curl -fsSL ${curlAuth}${url}public.gpg -o ${keyring}`,
    });
  }
  if (auth) {
    cli.push({
      title: `Credentials (/etc/apt/auth.conf.d/${r.name}.conf)`,
      code: `machine ${host}${path}\nlogin x\npassword <TOKEN>`,
    });
  }
  cli.push({
    title: 'Add the source',
    code: `echo "deb [signed-by=${keyring}] ${url} ${suite} ${comp}" \\\n  | sudo tee /etc/apt/sources.list.d/${r.name}.list\nsudo apt-get update && sudo apt-get install <package>`,
  });
  if (hosted) {
    cli.push({
      title: 'Upload a package',
      code: `curl -fu x:<TOKEN> -T ./pkg_1.0_amd64.deb \\\n  "${url}pkg_1.0_amd64.deb?distribution=${suite}&component=${comp}"`,
    });
  }
  const ci: Snippet[] = [
    {
      title: '.gitlab-ci.yml',
      code: hosted
        ? ciJob('publish-deb', 'curlimages/curl:latest', baseUrl, [
            `'curl -f -H "Authorization: Bearer $ENTREPOT_ID_TOKEN" -T dist/$CI_PROJECT_NAME.deb "${url}$CI_PROJECT_NAME.deb?distribution=${suite}&component=${comp}"'`,
          ])
        : ciJob('build', 'debian:12', baseUrl, [
            `printf 'machine ${host}${path}\\nlogin gitlab-ci\\npassword %s\\n' "$ENTREPOT_ID_TOKEN" > /etc/apt/auth.conf.d/entrepot.conf`,
            `echo "deb [signed-by=${keyring}] ${url} ${suite} ${comp}" > /etc/apt/sources.list.d/${r.name}.list`,
            'apt-get update && apt-get install -y <package>',
          ]),
    },
  ];
  return { cli, ci };
}

function yumSnippets(r: Repository, baseUrl: string, keyUrl: string): { cli: Snippet[]; ci: Snippet[] } {
  const url = r.url;
  const hosted = r.kind === 'hosted';
  const auth = !r.anonymousRead;
  const dir = yumDir(r.hosted?.yum?.repodataDepth ?? 0);
  const repoFile = [
    `[${r.name}]`,
    `name=${r.name}`,
    `baseurl=${url}${hosted ? dir : ''}`,
    'enabled=1',
    ...(hosted ? ['gpgcheck=0', 'repo_gpgcheck=1', `gpgkey=${keyUrl}`] : ['gpgcheck=1']),
    ...(auth ? ['username=x', 'password=<TOKEN>'] : []),
  ].join('\n');
  const cli: Snippet[] = [];
  if (hosted && !auth) {
    cli.push({
      title: 'Add the repository',
      code: `sudo curl -fsSL -o /etc/yum.repos.d/${r.name}.repo ${url}${dir}entrepot.repo\nsudo dnf install <package>`,
    });
  } else {
    cli.push({ title: `/etc/yum.repos.d/${r.name}.repo`, code: repoFile });
    cli.push({ title: 'Install', code: 'sudo dnf install <package>' });
  }
  if (hosted) {
    cli.push({
      title: 'Upload a package',
      code: `curl -fu x:<TOKEN> -T ./pkg-1.0-1.el9.x86_64.rpm \\\n  ${url}${dir}pkg-1.0-1.el9.x86_64.rpm`,
    });
  }
  const ci: Snippet[] = [
    {
      title: '.gitlab-ci.yml',
      code: hosted
        ? ciJob('publish-rpm', 'curlimages/curl:latest', baseUrl, [
            `'curl -f -H "Authorization: Bearer $ENTREPOT_ID_TOKEN" -T dist/$CI_PROJECT_NAME.rpm "${url}${dir}$CI_PROJECT_NAME.rpm"'`,
          ])
        : ciJob('build', 'rockylinux:9', baseUrl, [
            `printf '[${r.name}]\\nname=${r.name}\\nbaseurl=${url}\\ngpgcheck=1\\nusername=gitlab-ci\\npassword=%s\\n' "$ENTREPOT_ID_TOKEN" > /etc/yum.repos.d/${r.name}.repo`,
            'dnf install -y <package>',
          ]),
    },
  ];
  return { cli, ci };
}

function helmSnippets(r: Repository, baseUrl: string): { cli: Snippet[]; ci: Snippet[] } {
  const url = r.url;
  const hosted = r.kind === 'hosted';
  const auth = !r.anonymousRead;
  const creds = auth ? ' --username x --password <TOKEN>' : '';
  const cli: Snippet[] = [
    { title: 'Add the repository', code: `helm repo add ${r.name} ${url}${creds}\nhelm repo update` },
    { title: 'Install a chart', code: `helm search repo ${r.name}/\nhelm install my-release ${r.name}/<chart>` },
  ];
  if (hosted) {
    cli.push({
      title: 'Publish a chart',
      code: `helm package ./mychart\ncurl -f --data-binary @mychart-0.1.0.tgz \\\n  -H "Authorization: Bearer <TOKEN>" ${url}api/charts`,
    });
    cli.push({
      title: 'Or with the helm-push plugin (ChartMuseum API)',
      code: `helm plugin install https://github.com/chartmuseum/helm-push\nhelm cm-push mychart-0.1.0.tgz ${r.name}`,
    });
  }
  const ci: Snippet[] = [
    {
      title: '.gitlab-ci.yml',
      code: hosted
        ? ciJob('publish-chart', 'alpine/helm:3', baseUrl, [
            'helm package ./chart --version "$CI_COMMIT_TAG"',
            `'curl -f --data-binary @$(ls *.tgz) -H "Authorization: Bearer $ENTREPOT_ID_TOKEN" ${url}api/charts'`,
          ])
        : ciJob('deploy', 'alpine/helm:3', baseUrl, [
            `helm repo add ${r.name} ${url} --username gitlab-ci --password "$ENTREPOT_ID_TOKEN"`,
            `helm upgrade --install my-release ${r.name}/<chart>`,
          ]),
    },
  ];
  return { cli, ci };
}

function snippets(r: Repository, baseUrl: string, keyUrl: string): { cli: Snippet[]; ci: Snippet[] } {
  const url = r.url;
  const hosted = r.kind === 'hosted';
  const auth = !r.anonymousRead;
  const { host, path } = hostPath(url);
  const scheme = url.startsWith('https://') ? 'https://' : 'http://';

  switch (r.format) {
    case 'apt':
      return aptSnippets(r, baseUrl);
    case 'yum':
      return yumSnippets(r, baseUrl, keyUrl);
    case 'helm':
      return helmSnippets(r, baseUrl);
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
      // A Docker Hub proxy on its own hostname can be the daemon's mirror.
      if (r.docker?.host && r.kind === 'proxy' && /docker\.io/.test(r.proxy?.remoteUrl ?? '')) {
        cli.push({
          title: `Use as Docker Engine's mirror for Docker Hub (/etc/docker/daemon.json${r.anonymousRead ? '' : '; needs anonymous read'})`,
          code: JSON.stringify({ 'registry-mirrors': [`https://${r.docker.host}`] }, null, 2),
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

/**
 * The most useful single command for a repository (install / pull / download),
 * for compact "get started" hints such as the dashboard's repository cards.
 */
export function quickCommand(r: Repository, baseUrl: string): Snippet {
  const { cli } = snippets(r, baseUrl, `${r.url}public.key`);
  const pick =
    cli.find((s) => /^(install|pull|download|add)/i.test(s.title)) ??
    cli.find((s) => !s.code.includes('\n')) ??
    cli[0] ?? { title: 'URL', code: r.url };
  return { title: pick.title, code: pick.code.split('\n')[0] };
}

export function ClientSetup({ repository }: { repository: Repository }) {
  const { data: info } = useSystemInfo();
  const [mode, setMode] = useState<'cli' | 'ci'>('cli');
  const baseUrl = (info?.baseUrl || window.location.origin).replace(/\/+$/, '');
  const signed = repository.kind === 'hosted' && (repository.format === 'apt' || repository.format === 'yum');
  const key = useSigningKey(repository.name, signed);
  const keyUrl = key.data?.url || `${repository.url}public.key`;
  const s = snippets(repository, baseUrl, keyUrl);
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
