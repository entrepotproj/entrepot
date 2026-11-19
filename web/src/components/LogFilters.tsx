import { ActionIcon, Button, Group, Select, TextInput, Tooltip } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconCalendar, IconFileTypeCsv, IconX } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router';

/** A URL search parameter as state (empty string = unset). */
export function useParamState(key: string): [string, (v: string) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get(key) ?? '';
  const set = (v: string) => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (v) next.set(key, v);
        else next.delete(key);
        return next;
      },
      { replace: true },
    );
  };
  return [value, set];
}

/** A text filter bound to a URL parameter, applied after the user pauses typing. */
export function DebouncedParamInput({
  param,
  label,
  placeholder,
  w = 180,
  mono,
}: {
  param: string;
  label: string;
  placeholder?: string;
  w?: number;
  mono?: boolean;
}) {
  const [value, setValue] = useParamState(param);
  const [text, setText] = useState(value);
  const [debounced] = useDebouncedValue(text, 350);
  useEffect(() => {
    if (debounced.trim() !== value) setValue(debounced.trim());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);
  useEffect(() => {
    // External reset (e.g. "Clear filters").
    if (value === '' && text.trim() !== '' && debounced === text) setText('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return (
    <TextInput
      size="xs"
      label={label}
      placeholder={placeholder}
      value={text}
      onChange={(e) => setText(e.currentTarget.value)}
      w={w}
      styles={mono ? { input: { fontFamily: 'var(--mantine-font-family-monospace)' } } : undefined}
      rightSection={
        text ? (
          <ActionIcon size="xs" variant="subtle" color="gray" onClick={() => setText('')} aria-label={`Clear ${label}`}>
            <IconX size={12} />
          </ActionIcon>
        ) : null
      }
    />
  );
}

/** datetime-local value (local time, no zone) <-> RFC 3339. */
export function localToIso(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

const PRESETS = [
  { value: '1h', label: 'Last hour', ms: 3600_000 },
  { value: '24h', label: 'Last 24 hours', ms: 86400_000 },
  { value: '7d', label: 'Last 7 days', ms: 7 * 86400_000 },
  { value: '30d', label: 'Last 30 days', ms: 30 * 86400_000 },
];

function toLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** From / to inputs bound to the `from` and `to` URL parameters (local datetime), plus quick presets. */
export function DateRangeFilter() {
  const [from, setFrom] = useParamState('from');
  const [to, setTo] = useParamState('to');
  const [, setParams] = useSearchParams();
  return (
    <Group gap="xs" align="flex-end" wrap="wrap">
      <Select
        size="xs"
        label="Period"
        placeholder="Any time"
        w={130}
        data={PRESETS.map((p) => ({ value: p.value, label: p.label }))}
        value={null}
        onChange={(v) => {
          const p = PRESETS.find((x) => x.value === v);
          if (!p) return;
          setParams(
            (prev) => {
              const next = new URLSearchParams(prev);
              next.set('from', toLocalInput(new Date(Date.now() - p.ms)));
              next.delete('to');
              return next;
            },
            { replace: true },
          );
        }}
        leftSection={<IconCalendar size={14} />}
        comboboxProps={{ withinPortal: true }}
        allowDeselect={false}
      />
      <TextInput size="xs" type="datetime-local" label="From" value={from} onChange={(e) => setFrom(e.currentTarget.value)} w={172} />
      <TextInput size="xs" type="datetime-local" label="To" value={to} onChange={(e) => setTo(e.currentTarget.value)} w={172} />
    </Group>
  );
}

export function ExportCsvButton({ href, max }: { href: string; max: number }) {
  return (
    <Tooltip label={`Download the newest ${max.toLocaleString()} matching rows as CSV`} withArrow>
      <Button
        component="a"
        href={href}
        download
        variant="default"
        leftSection={<IconFileTypeCsv size={16} />}
      >
        Export CSV
      </Button>
    </Tooltip>
  );
}

export function ClearFiltersButton({ keys, active }: { keys: string[]; active: boolean }) {
  const [, setParams] = useSearchParams();
  if (!active) return null;
  return (
    <Button
      size="xs"
      variant="subtle"
      color="gray"
      leftSection={<IconX size={14} />}
      onClick={() =>
        setParams(
          (prev) => {
            const next = new URLSearchParams(prev);
            keys.forEach((k) => next.delete(k));
            return next;
          },
          { replace: true },
        )
      }
    >
      Clear filters
    </Button>
  );
}
