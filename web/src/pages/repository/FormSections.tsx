import {
  ActionIcon,
  Alert,
  Anchor,
  Button,
  Code,
  Group,
  MultiSelect,
  NumberInput,
  Paper,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  TagsInput,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core';
import { IconInfoCircle, IconPlus, IconShieldLock, IconX } from '@tabler/icons-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { isNotImplemented } from '../../api/client';
import { useCleanupPolicies, useRoutingRules, useScanners } from '../../api/queries';
import { formatLabel } from '../../components/badges';
import { NotAvailable } from '../../components/states';
import { useAuth } from '../../lib/auth';

export type AptDist = { name: string; components: string[]; architectures: string[]; origin: string; label: string };

export const DEFAULT_APT_DIST: AptDist = {
  name: 'stable',
  components: ['main'],
  architectures: ['amd64', 'arm64', 'all'],
  origin: '',
  label: '',
};

const ARCHES = ['amd64', 'arm64', 'armhf', 'i386', 'ppc64el', 's390x', 'riscv64', 'all'];

export function AptDistributionsEditor({ value, onChange }: { value: AptDist[]; onChange: (v: AptDist[]) => void }) {
  const update = (i: number, patch: Partial<AptDist>) => onChange(value.map((d, j) => (j === i ? { ...d, ...patch } : d)));
  const names = value.map((d) => d.name.trim()).filter(Boolean);
  const dupes = names.length !== new Set(names).size;
  return (
    <Stack gap="sm">
      {value.map((d, i) => (
        <Paper key={i} p="sm" bg="var(--mantine-color-default-hover)">
          <Group align="flex-start" wrap="nowrap" gap="sm">
            <SimpleGrid cols={{ base: 1, sm: 3 }} style={{ flex: 1 }} spacing="sm">
              <TextInput
                label="Distribution (suite)"
                placeholder="stable"
                value={d.name}
                onChange={(e) => update(i, { name: e.currentTarget.value.trim() })}
                error={!d.name.trim() ? 'Required' : null}
                styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
              />
              <TagsInput
                label="Components"
                placeholder={d.components.length ? undefined : 'main'}
                data={['main', 'contrib', 'non-free', 'testing']}
                value={d.components}
                onChange={(v) => update(i, { components: v })}
              />
              <TagsInput
                label="Architectures"
                placeholder={d.architectures.length ? undefined : 'amd64'}
                data={ARCHES}
                value={d.architectures}
                onChange={(v) => update(i, { architectures: v })}
              />
              <TextInput
                label="Origin"
                placeholder="optional"
                value={d.origin}
                onChange={(e) => update(i, { origin: e.currentTarget.value })}
              />
              <TextInput
                label="Label"
                placeholder="optional"
                value={d.label}
                onChange={(e) => update(i, { label: e.currentTarget.value })}
              />
            </SimpleGrid>
            <Tooltip label="Remove distribution">
              <ActionIcon
                variant="subtle"
                color="red"
                mt={26}
                onClick={() => onChange(value.filter((_, j) => j !== i))}
                aria-label="Remove distribution"
              >
                <IconX size={16} />
              </ActionIcon>
            </Tooltip>
          </Group>
        </Paper>
      ))}
      {dupes && (
        <Text size="xs" c="red">
          Distribution names must be unique.
        </Text>
      )}
      <Group>
        <Button
          size="xs"
          variant="light"
          leftSection={<IconPlus size={14} />}
          onClick={() =>
            onChange([...value, { ...DEFAULT_APT_DIST, name: value.length === 0 ? 'stable' : '', components: ['main'] }])
          }
        >
          Add distribution
        </Button>
        {value.length === 0 && (
          <Text size="xs" c="dimmed">
            Without distributions, a default <Code>stable</Code> distribution with component <Code>main</Code> is
            published.
          </Text>
        )}
      </Group>
    </Stack>
  );
}

export type ScanForm = {
  scanners: string[];
  mode: 'off' | 'warn' | 'quarantine';
  severityThreshold: string;
  onUpload: boolean;
  onProxyFetch: boolean;
  blockUntilScanned: boolean;
  blockOnError: boolean;
  holdSeconds: number;
  distro: string;
};

/** Suggested hold per format: what each client tolerates before timing out. */
export const HOLD_SUGGESTION: Record<string, number> = { pypi: 10, apt: 20, yum: 20, docker: 300 };

const DISTRO_EXAMPLES: Record<string, string[]> = {
  apt: ['debian-12', 'debian-11', 'ubuntu-24.04', 'ubuntu-22.04'],
  yum: ['rocky-9', 'rhel-9', 'alma-9', 'centos-7', 'fedora-40', 'amazon-2023'],
};

const MODE_HELP: Record<string, string> = {
  off: 'Scanners are configured but nothing is scanned.',
  warn: 'Components are scanned and findings are recorded, but downloads are never blocked.',
  quarantine:
    'Components with findings at or above the threshold are quarantined: clients get an error instead of the artifact until the findings are fixed or waived.',
};

function SubHeading({ children }: { children: ReactNode }) {
  return (
    <Text size="sm" fw={600}>
      {children}
    </Text>
  );
}

/** Repository scanning settings. */
export function ScanFields({
  value,
  onChange,
  format,
  kind,
}: {
  value: ScanForm;
  onChange: (patch: Partial<ScanForm>) => void;
  format: string;
  kind: string;
}) {
  const { admin } = useAuth();
  const scanners = useScanners(admin);
  if (scanners.error && isNotImplemented(scanners.error)) return <NotAvailable feature="Vulnerability scanning" compact />;

  const options = (scanners.data ?? []).map((s) => ({
    value: s.name,
    label: `${s.name} (${s.type}${s.enabled ? '' : ', disabled'})`,
  }));
  // Keep configured scanners selectable even if the list could not be loaded.
  for (const n of value.scanners) if (!options.some((o) => o.value === n)) options.push({ value: n, label: n });

  const enabled = value.scanners.length > 0;
  return (
    <Stack gap="md">
      <MultiSelect
        label="Scanners"
        description="Every selected scanner runs on each component. Leave empty to disable scanning."
        placeholder={value.scanners.length ? undefined : scanners.isPending ? 'Loading…' : 'No scanning'}
        data={options}
        value={value.scanners}
        onChange={(v) => onChange({ scanners: v })}
        searchable
        clearable
        nothingFoundMessage={
          <Text size="xs">
            No scanners.{' '}
            <Anchor component={Link} to="/admin/scanners" size="xs">
              Configure one
            </Anchor>
          </Text>
        }
        error={scanners.error ? 'Could not load scanners' : null}
      />
      {scanners.data && scanners.data.length === 0 && (
        <Text size="xs" c="dimmed">
          No scanners are configured yet.{' '}
          <Anchor component={Link} to="/admin/scanners" size="xs">
            Add a Trivy, Grype or webhook scanner
          </Anchor>{' '}
          to enable vulnerability scanning.
        </Text>
      )}
      <div style={{ opacity: enabled ? 1 : 0.55 }}>
        <Stack gap="md">
          <div>
            <SubHeading>Mode</SubHeading>
            <SegmentedControl
              mt={6}
              value={value.mode}
              onChange={(v) => onChange({ mode: v as ScanForm['mode'] })}
              disabled={!enabled}
              data={[
                { value: 'off', label: 'Off' },
                { value: 'warn', label: 'Warn' },
                { value: 'quarantine', label: 'Quarantine' },
              ]}
            />
            <Text size="xs" c="dimmed" mt={6}>
              {MODE_HELP[value.mode]}
            </Text>
          </div>
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <Select
              label="Severity threshold"
              description={
                value.mode === 'quarantine'
                  ? 'Quarantine components with findings at or above this severity'
                  : 'Findings at or above this severity mark a component vulnerable'
              }
              data={[
                { value: 'critical', label: 'Critical' },
                { value: 'high', label: 'High and above' },
                { value: 'medium', label: 'Medium and above' },
                { value: 'low', label: 'Low and above' },
              ]}
              value={value.severityThreshold}
              onChange={(v) => v && onChange({ severityThreshold: v })}
              allowDeselect={false}
              disabled={!enabled}
            />
            {(format === 'apt' || format === 'yum') && (
              <TextInput
                label="Distribution for matching"
                description={
                  <>
                    Vulnerability data to match packages against, e.g.{' '}
                    {DISTRO_EXAMPLES[format].map((d, i) => (
                      <span key={d}>
                        {i > 0 && ', '}
                        <Code fz={11}>{d}</Code>
                      </span>
                    ))}
                  </>
                }
                placeholder={DISTRO_EXAMPLES[format][0]}
                value={value.distro}
                onChange={(e) => onChange({ distro: e.currentTarget.value.trim() })}
                disabled={!enabled}
              />
            )}
          </SimpleGrid>
          <Group gap="xl" align="flex-start">
            {kind !== 'proxy' && (
              <Switch
                label="Scan on upload"
                description="Scan components when they are published"
                checked={value.onUpload}
                onChange={(e) => onChange({ onUpload: e.currentTarget.checked })}
                disabled={!enabled}
              />
            )}
            {kind !== 'hosted' && (
              <Switch
                label="Scan on proxy fetch"
                description="Scan components when first cached from the remote"
                checked={value.onProxyFetch}
                onChange={(e) => onChange({ onProxyFetch: e.currentTarget.checked })}
                disabled={!enabled}
              />
            )}
            <Switch
              label="Block until scanned"
              description="Quarantine mode: refuse downloads until the first scan completes"
              checked={value.blockUntilScanned}
              onChange={(e) => onChange({ blockUntilScanned: e.currentTarget.checked })}
              disabled={!enabled || value.mode !== 'quarantine'}
            />
            <Switch
              label="Hold downloads for the verdict"
              description="Keep a download of content that is still being scanned open until the scan finishes, instead of refusing it"
              checked={value.holdSeconds > 0}
              onChange={(e) =>
                onChange({ holdSeconds: e.currentTarget.checked ? (HOLD_SUGGESTION[format] ?? 60) : 0 })
              }
              disabled={!enabled || value.mode !== 'quarantine' || !value.blockUntilScanned}
            />
            {value.holdSeconds > 0 && (
              <NumberInput
                label="Hold for up to (seconds)"
                description="Then the client gets 503 and retries. Keep it below your load balancer's idle timeout and the client's read timeout (pip: 15s)."
                min={1}
                max={600}
                w={260}
                value={value.holdSeconds}
                onChange={(v) => onChange({ holdSeconds: typeof v === 'number' ? v : 0 })}
                disabled={!enabled || value.mode !== 'quarantine' || !value.blockUntilScanned}
              />
            )}
            <Switch
              label="Block on scan errors"
              description="Quarantine mode: refuse downloads while a configured scanner's latest scan failed; failed scans are retried"
              checked={value.blockOnError}
              onChange={(e) => onChange({ blockOnError: e.currentTarget.checked })}
              disabled={!enabled || value.mode !== 'quarantine'}
            />
          </Group>
          {kind === 'group' && (
            <Text size="xs" c="dimmed">
              Group repositories do not store components; scanning applies to the member repositories.
            </Text>
          )}
        </Stack>
      </div>
    </Stack>
  );
}

/** Cleanup policy multi-select. */
export function CleanupFields({
  value,
  onChange,
  format,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  format: string;
}) {
  const { admin } = useAuth();
  const policies = useCleanupPolicies(admin);
  if (policies.error && isNotImplemented(policies.error)) return <NotAvailable feature="Cleanup policies" compact />;
  const options = (policies.data ?? [])
    .filter((p) => !p.format || p.format === format || value.includes(p.name))
    .map((p) => ({ value: p.name, label: p.format ? `${p.name} (${formatLabel(p.format)} only)` : p.name }));
  for (const n of value) if (!options.some((o) => o.value === n)) options.push({ value: n, label: n });
  return (
    <Stack gap={6}>
      <MultiSelect
        label="Cleanup policies"
        description="Components matching any selected policy are deleted when cleanup runs."
        placeholder={value.length ? undefined : policies.isPending ? 'Loading…' : 'No automatic cleanup'}
        data={options}
        value={value}
        onChange={onChange}
        searchable
        clearable
        nothingFoundMessage="No matching policies"
        error={policies.error ? 'Could not load cleanup policies' : null}
      />
      {policies.data && policies.data.length === 0 && (
        <Text size="xs" c="dimmed">
          No cleanup policies yet.{' '}
          <Anchor component={Link} to="/admin/cleanup-policies" size="xs">
            Create one
          </Anchor>
          .
        </Text>
      )}
    </Stack>
  );
}

/** Routing rule select for proxies. */
export function RoutingRuleField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { admin } = useAuth();
  const rules = useRoutingRules(admin);
  if (rules.error && isNotImplemented(rules.error)) return <NotAvailable feature="Routing rules" compact />;
  const options = (rules.data ?? []).map((r) => ({ value: r.name, label: `${r.name} (${r.mode})` }));
  if (value && !options.some((o) => o.value === value)) options.push({ value, label: value });
  return (
    <Select
      label="Routing rule"
      description={
        <>
          Limit which packages are fetched from the remote, e.g. never fetch your internal <Code fz={11}>@acme/*</Code>{' '}
          scope upstream.{' '}
          <Anchor component={Link} to="/admin/routing-rules" size="xs">
            Manage rules
          </Anchor>
        </>
      }
      placeholder={rules.isPending ? 'Loading…' : 'None — everything may be fetched upstream'}
      data={options}
      value={value || null}
      onChange={(v) => onChange(v ?? '')}
      clearable
      error={rules.error ? 'Could not load routing rules' : null}
    />
  );
}

export function PreferHostedField({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <Stack gap="xs">
      <Switch
        label="Prefer hosted packages"
        description="If any hosted member has a package name, never serve that name from proxy members."
        checked={checked}
        onChange={(e) => onChange(e.currentTarget.checked)}
      />
      <Alert variant="light" color={checked ? 'blue' : 'orange'} icon={checked ? <IconShieldLock size={18} /> : <IconInfoCircle size={18} />} p="sm">
        <Text size="xs">
          <b>Dependency confusion protection.</b> An attacker can publish a public package with the same name as one of
          your internal packages and a higher version number. Without this setting, the group may serve the public one
          from a proxy member. With it on, a package name that exists in a hosted member is only ever resolved from
          hosted members.
        </Text>
      </Alert>
    </Stack>
  );
}
