import { Anchor, Breadcrumbs, Group, Stack, Text, Title } from '@mantine/core';
import { useEffect, type ReactNode } from 'react';
import { Link } from 'react-router';

export type Crumb = { label: string; to?: string };

export function PageHeader({
  title,
  description,
  actions,
  crumbs,
  icon,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  crumbs?: Crumb[];
  icon?: ReactNode;
}) {
  const docTitle = typeof title === 'string' ? title : crumbs?.[crumbs.length - 1]?.label;
  useEffect(() => {
    document.title = docTitle ? `${docTitle} · Entrepot` : 'Entrepot';
  }, [docTitle]);
  return (
    <Stack gap={6} mb="lg">
      {crumbs && crumbs.length > 0 && (
        <Breadcrumbs separatorMargin={6} fz="sm">
          {crumbs.map((c, i) =>
            c.to ? (
              <Anchor key={i} component={Link} to={c.to} size="sm" c="dimmed">
                {c.label}
              </Anchor>
            ) : (
              <Text key={i} size="sm" c="dimmed">
                {c.label}
              </Text>
            ),
          )}
        </Breadcrumbs>
      )}
      <Group justify="space-between" align="flex-start" wrap="wrap" gap="sm">
        <Group gap="sm" wrap="nowrap" align="center">
          {icon}
          <Stack gap={2}>
            <Title order={2} fw={650} style={{ wordBreak: 'break-word' }}>
              {title}
            </Title>
            {description && (
              <Text c="dimmed" size="sm">
                {description}
              </Text>
            )}
          </Stack>
        </Group>
        {actions && <Group gap="xs">{actions}</Group>}
      </Group>
    </Stack>
  );
}
