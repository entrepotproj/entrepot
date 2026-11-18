import { Badge, type BadgeProps, Tooltip } from '@mantine/core';
import {
  IconArrowsShuffle,
  IconBrandDocker,
  IconBrandNpm,
  IconBrandPython,
  IconCloudDownload,
  IconDatabase,
  IconFile,
  IconPackage,
  IconStack2,
  type Icon,
} from '@tabler/icons-react';

type IconT = Icon;

const formats: Record<string, { color: string; icon: IconT; label: string }> = {
  raw: { color: 'gray', icon: IconFile, label: 'Raw' },
  pypi: { color: 'blue', icon: IconBrandPython, label: 'PyPI' },
  npm: { color: 'red', icon: IconBrandNpm, label: 'npm' },
  docker: { color: 'cyan', icon: IconBrandDocker, label: 'Docker' },
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
