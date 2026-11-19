import { Code, Text } from '@mantine/core';

export function JsonView({ value }: { value: unknown }) {
  const empty = value == null || (typeof value === 'object' && Object.keys(value as object).length === 0);
  if (empty) {
    return (
      <Text size="sm" c="dimmed">
        No attributes
      </Text>
    );
  }
  return (
    <Code block fz="xs" style={{ maxHeight: 360, overflow: 'auto' }}>
      {JSON.stringify(value, null, 2)}
    </Code>
  );
}
