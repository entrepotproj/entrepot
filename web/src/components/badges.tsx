import { Badge, type BadgeProps, Tooltip } from '@mantine/core';
import {
  IconAlertTriangle,
  IconArrowsShuffle,
  IconBrandDebian,
  IconBug,
  IconBrandDocker,
  IconBrandRedhat,
  IconBrandNpm,
  IconBrandPython,
  IconCloudDownload,
  IconDatabase,
  IconFile,
  IconHourglass,
  IconLock,
  IconPackage,
  IconShieldCheck,
  IconShieldExclamation,
  IconShieldOff,
  IconShieldQuestion,
  IconStack2,
  IconSteeringWheel,
  IconTerminal2,
  IconWebhook,
  type Icon,
} from '@tabler/icons-react';

type IconT = Icon;

const formats: Record<string, { color: string; icon: IconT; label: string }> = {
  raw: { color: 'gray', icon: IconFile, label: 'Raw' },
  pypi: { color: 'blue', icon: IconBrandPython, label: 'PyPI' },
  npm: { color: 'red', icon: IconBrandNpm, label: 'npm' },
  docker: { color: 'cyan', icon: IconBrandDocker, label: 'Docker' },
  apt: { color: 'pink', icon: IconBrandDebian, label: 'Apt' },
  yum: { color: 'grape', icon: IconBrandRedhat, label: 'Yum' },
  helm: { color: 'indigo', icon: IconSteeringWheel, label: 'Helm' },
};

export function formatLabel(f: string): string {
  return formats[f]?.label ?? f;
}

export function FormatIcon({ format, size = 18 }: { format: string; size?: number }) {
  const Icon = formats[format]?.icon ?? IconPackage;
  return <Icon size={size} stroke={1.6} />;
}

export function FormatBadge({ format, ...rest }: { format: string } & BadgeProps) {
  const f = formats[format];
  const Icon = f?.icon ?? IconPackage;
  return (
    <Badge
      variant="light"
      color={f?.color ?? 'gray'}
      leftSection={<Icon size={13} stroke={1.8} />}
      radius="sm"
      tt="none"
      {...rest}
    >
      {f?.label ?? format}
    </Badge>
  );
}

const kinds: Record<string, { color: string; icon: IconT; help: string }> = {
  hosted: { color: 'teal', icon: IconDatabase, help: 'Stores artifacts published to it' },
  proxy: { color: 'violet', icon: IconCloudDownload, help: 'Caches artifacts from a remote registry' },
  group: { color: 'orange', icon: IconStack2, help: 'Merges several repositories behind one URL' },
};

export function KindBadge({ kind, ...rest }: { kind: string } & BadgeProps) {
  const k = kinds[kind];
  const Icon = k?.icon ?? IconArrowsShuffle;
  return (
    <Tooltip label={k?.help ?? kind} withArrow openDelay={400}>
      <Badge variant="outline" color={k?.color ?? 'gray'} leftSection={<Icon size={12} />} radius="sm" tt="none" {...rest}>
        {kind}
      </Badge>
    </Tooltip>
  );
}

export function kindHelp(kind: string) {
  return kinds[kind]?.help ?? '';
}

export function OnlineBadge({ online }: { online: boolean }) {
  return (
    <Badge variant="dot" color={online ? 'teal' : 'gray'} tt="none" radius="sm">
      {online ? 'Online' : 'Offline'}
    </Badge>
  );
}

// ---- Scanning ----

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const;

const severityColors: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'yellow',
  low: 'blue',
  unknown: 'gray',
};

export function severityColor(s: string): string {
  return severityColors[s] ?? 'gray';
}

export function SeverityBadge({ severity, ...rest }: { severity: string } & BadgeProps) {
  return (
    <Badge variant="light" color={severityColor(severity)} radius="sm" {...rest}>
      {severity}
    </Badge>
  );
}

const scanStates: Record<string, { color: string; icon: IconT; label: string; help: string; variant: string }> = {
  clean: { color: 'teal', icon: IconShieldCheck, label: 'Clean', help: 'No findings at or above the threshold', variant: 'light' },
  vulnerable: {
    color: 'red',
    icon: IconShieldExclamation,
    label: 'Vulnerable',
    help: 'The latest scan reported vulnerabilities',
    variant: 'light',
  },
  pending: { color: 'blue', icon: IconHourglass, label: 'Pending', help: 'A scan is queued or running', variant: 'light' },
  error: { color: 'gray', icon: IconAlertTriangle, label: 'Error', help: 'The last scan failed', variant: 'light' },
  unscanned: { color: 'gray', icon: IconShieldQuestion, label: 'Unscanned', help: 'Not scanned yet', variant: 'subtle' },
  unsupported: {
    color: 'gray',
    icon: IconShieldOff,
    label: 'Unsupported',
    help: 'No configured scanner can scan this kind of artifact',
    variant: 'subtle',
  },
};

/** Scan state badge; orange instead of red when vulnerable but only below-threshold (not quarantined). */
export function ScanStateBadge({
  state,
  quarantined,
  ...rest
}: { state?: string | null; quarantined?: boolean } & BadgeProps) {
  const st = scanStates[state ?? 'unscanned'] ?? scanStates.unscanned;
  const Icon = quarantined ? IconLock : st.icon;
  const color = state === 'vulnerable' && !quarantined ? 'orange' : st.color;
  return (
    <Tooltip label={quarantined ? `Quarantined — downloads are blocked. ${st.help}.` : st.help} withArrow openDelay={300}>
      <Badge
        variant={st.variant}
        color={quarantined ? 'red' : color}
        leftSection={<Icon size={12} stroke={1.8} />}
        radius="sm"
        tt="none"
        {...rest}
      >
        {st.label}
        {quarantined ? ' · quarantined' : ''}
      </Badge>
    </Tooltip>
  );
}

const scannerTypes: Record<string, { color: string; icon: IconT; label: string }> = {
  trivy: { color: 'cyan', icon: IconShieldCheck, label: 'Trivy' },
  grype: { color: 'violet', icon: IconTerminal2, label: 'Grype' },
  webhook: { color: 'orange', icon: IconWebhook, label: 'Webhook' },
  metadefender: { color: 'grape', icon: IconBug, label: 'MetaDefender' },
};

export function ScannerTypeBadge({ type, ...rest }: { type: string } & BadgeProps) {
  const t = scannerTypes[type];
  const Icon = t?.icon ?? IconShieldCheck;
  return (
    <Badge variant="light" color={t?.color ?? 'gray'} leftSection={<Icon size={12} />} radius="sm" tt="none" {...rest}>
      {t?.label ?? type}
    </Badge>
  );
}

const jobStatus: Record<string, string> = { queued: 'blue', running: 'cyan', done: 'teal', failed: 'red' };

export function JobStatusBadge({ status, ...rest }: { status: string } & BadgeProps) {
  return (
    <Badge variant={status === 'running' ? 'dot' : 'light'} color={jobStatus[status] ?? 'gray'} radius="sm" tt="none" {...rest}>
      {status}
    </Badge>
  );
}
