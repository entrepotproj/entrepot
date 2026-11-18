import { Table, Text } from '@mantine/core';
import type { ReactNode } from 'react';

/** A two-column key/value list. */
export function DetailList({ items }: { items: [string, ReactNode][] }) {
  return (
    <Table verticalSpacing={6} withRowBorders={false} layout="fixed">
      <Table.Tbody>
        {items.map(([k, v]) => (
          <Table.Tr key={k}>
            <Table.Td w={160} valign="top">
              <Text size="sm" c="dimmed">
                {k}
              </Text>
            </Table.Td>
            <Table.Td style={{ wordBreak: 'break-all' }}>{typeof v === 'string' ? <Text size="sm">{v}</Text> : v}</Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </Table>
  );
}
