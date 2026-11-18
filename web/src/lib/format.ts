const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

export function formatBytes(n: number | undefined | null): string {
  if (n == null || Number.isNaN(n)) return '—';
  if (n < 1024) return `${n} B`;
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[i]}`;
}

const numberFmt = new Intl.NumberFormat();

export function formatNumber(n: number | undefined | null): string {
  return n == null ? '—' : numberFmt.format(n);
}

const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const relFmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

export function formatDate(s: string | undefined | null): string {
  if (!s) return '—';
  const d = new Date(s);
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1971) return '—';
  return dateFmt.format(d);
}

export function formatRelative(s: string | undefined | null): string {
  if (!s) return '—';
  const d = new Date(s);
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1971) return '—';
  const sec = Math.round((d.getTime() - Date.now()) / 1000);
  const abs = Math.abs(sec);
  if (abs < 60) return relFmt.format(sec, 'second');
  if (abs < 3600) return relFmt.format(Math.round(sec / 60), 'minute');
  if (abs < 86400) return relFmt.format(Math.round(sec / 3600), 'hour');
  if (abs < 86400 * 30) return relFmt.format(Math.round(sec / 86400), 'day');
  if (abs < 86400 * 365) return relFmt.format(Math.round(sec / (86400 * 30)), 'month');
  return relFmt.format(Math.round(sec / (86400 * 365)), 'year');
}

export function formatDuration(seconds: number | undefined | null): string {
  if (seconds == null) return '—';
  if (seconds < 0) return 'disabled';
  if (seconds === 0) return 'never expires';
  if (seconds % 86400 === 0) return `${seconds / 86400} d`;
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}

/** Last path segment. */
export function baseName(p: string): string {
  const t = p.replace(/\/+$/, '');
  const i = t.lastIndexOf('/');
  return i >= 0 ? t.slice(i + 1) : t;
}

/** Directory part of a path, ending in "/" (or "" for the root). */
export function dirName(p: string): string {
  const i = p.lastIndexOf('/');
  return i >= 0 ? p.slice(0, i + 1) : '';
}
