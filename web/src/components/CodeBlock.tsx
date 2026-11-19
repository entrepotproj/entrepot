import { ActionIcon, Box, Code, CopyButton, Group, Text, Tooltip } from '@mantine/core';
import { IconCheck, IconCopy } from '@tabler/icons-react';

export function CopyIcon({ value, label = 'Copy' }: { value: string; label?: string }) {
  return (
    <CopyButton value={value} timeout={1500}>
      {({ copied, copy }) => (
        <Tooltip label={copied ? 'Copied' : label} withArrow position="top">
          <ActionIcon
            variant="subtle"
            color={copied ? 'teal' : 'gray'}
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              e.preventDefault();
              copy();
            }}
            aria-label={label}
          >
            {copied ? <IconCheck size={15} /> : <IconCopy size={15} />}
          </ActionIcon>
        </Tooltip>
      )}
    </CopyButton>
  );
}

/** A multi-line code snippet with a copy button. */
export function CodeBlock({ code, title }: { code: string; title?: string }) {
  if (title) {
    return (
      <Box>
        <Group justify="space-between" mb={4} wrap="nowrap">
          <Text size="xs" fw={600} c="dimmed" tt="uppercase" style={{ letterSpacing: 0.4 }}>
            {title}
          </Text>
          <CopyIcon value={code} />
        </Group>
        <Code block fz="xs" style={{ whiteSpace: 'pre', overflowX: 'auto' }}>
          {code}
        </Code>
      </Box>
    );
  }
  return (
    <Box pos="relative">
      <Code block fz="xs" style={{ whiteSpace: 'pre', overflowX: 'auto', paddingRight: 40 }}>
        {code}
      </Code>
      <Box pos="absolute" top={6} right={6}>
        <CopyIcon value={code} />
      </Box>
    </Box>
  );
}

/** Inline monospace value with a copy button. */
export function CopyText({ value, maw }: { value: string; maw?: number | string }) {
  return (
    <Group gap={4} wrap="nowrap" maw={maw}>
      <Text ff="monospace" fz="xs" truncate="end" title={value}>
        {value}
      </Text>
      <CopyIcon value={value} />
    </Group>
  );
}
