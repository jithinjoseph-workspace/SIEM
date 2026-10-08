const timeFormatter = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

export function parseTimestamp(value: unknown): Date | null {
  if (value === null || value === undefined || value === '') {
    return null;
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }

  if (typeof value === 'number') {
    const milliseconds = value < 1_000_000_000_000 ? value * 1000 : value;
    const parsed = new Date(milliseconds);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }

    if (/^\d+$/.test(trimmed)) {
      return parseTimestamp(Number(trimmed));
    }

    const normalized = trimmed.includes('T')
      ? trimmed
      : `${trimmed.replace(' ', 'T')}Z`;
    const parsed = new Date(normalized);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  return null;
}

export function formatTimestampTime(value: unknown, fallback = '-'): string {
  const parsed = parseTimestamp(value);
  return parsed ? timeFormatter.format(parsed) : fallback;
}

export function formatTimestampDateTime(value: unknown, fallback = '-'): string {
  const parsed = parseTimestamp(value);
  return parsed ? dateTimeFormatter.format(parsed) : fallback;
}

export function toUnixSeconds(value: unknown): number | null {
  const parsed = parseTimestamp(value);
  return parsed ? Math.floor(parsed.getTime() / 1000) : null;
}
