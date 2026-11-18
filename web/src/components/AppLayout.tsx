import {
  ActionIcon,
  AppShell,
  Avatar,
  Badge,
  Box,
  Burger,
  Button,
  Divider,
  Group,
  Menu,
  NavLink,
  ScrollArea,
  Skeleton,
  Text,
  ThemeIcon,
  Tooltip,
  UnstyledButton,
  useComputedColorScheme,
  useMantineColorScheme,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import {
  IconBook2,
  IconBrandGitlab,
  IconChevronDown,
  IconDatabase,
  IconEraser,
  IconHistory,
  IconKey,
  IconListCheck,
  IconLogin,
  IconLogout,
  IconMoon,
  IconPackages,
  IconRadar2,
  IconRobot,
  IconRoute,
  IconSearch,
  IconShieldLock,
  IconShieldOff,
  IconSun,
  IconUsers,
  type Icon,
} from '@tabler/icons-react';
import { useQueryClient } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router';
import { sessionLogout } from '../api/client';
import { useSystemInfo } from '../api/queries';
import { useAuth } from '../lib/auth';

type NavItem = { to: string; label: string; icon: Icon };

const browseNav: NavItem[] = [
  { to: '/repositories', label: 'Repositories', icon: IconPackages },
  { to: '/search', label: 'Search', icon: IconSearch },
];

const adminNav: NavItem[] = [
  { to: '/admin/blob-stores', label: 'Blob stores', icon: IconDatabase },
  { to: '/admin/cleanup-policies', label: 'Cleanup policies', icon: IconEraser },
  { to: '/admin/routing-rules', label: 'Routing rules', icon: IconRoute },
  { to: '/admin/roles', label: 'Roles & bindings', icon: IconShieldLock },
  { to: '/admin/gitlab', label: 'GitLab trust', icon: IconBrandGitlab },
  { to: '/admin/service-accounts', label: 'Service accounts', icon: IconRobot },
  { to: '/admin/users', label: 'Users', icon: IconUsers },
  { to: '/admin/audit', label: 'Audit log', icon: IconHistory },
];

const securityNav: NavItem[] = [
  { to: '/admin/scanners', label: 'Scanners', icon: IconRadar2 },
  { to: '/admin/waivers', label: 'Waivers', icon: IconShieldOff },
  { to: '/admin/scan-jobs', label: 'Scan jobs', icon: IconListCheck },
];

export function Logo() {
  return (
    <Group gap={8} wrap="nowrap">
      <ThemeIcon size={30} radius="md" variant="gradient" gradient={{ from: 'blue.6', to: 'cyan.5', deg: 135 }}>
        <svg viewBox="0 0 32 32" width="20" height="20" aria-hidden>
          <path d="M8 12.5 16 8l8 4.5v9L16 26l-8-4.5z" fill="none" stroke="#fff" strokeWidth="2.2" strokeLinejoin="round" />
          <path d="M8 12.5 16 17l8-4.5M16 17v9" fill="none" stroke="#fff" strokeWidth="2.2" strokeLinejoin="round" />
        </svg>
      </ThemeIcon>
      <Text fw={700} size="lg" style={{ letterSpacing: -0.3 }}>
        Entrepot
      </Text>
    </Group>
  );
}

function ColorSchemeToggle() {
  const { setColorScheme } = useMantineColorScheme();
  const computed = useComputedColorScheme('light', { getInitialValueInEffect: true });
  const dark = computed === 'dark';
  return (
    <Tooltip label={dark ? 'Light mode' : 'Dark mode'} withArrow>
      <ActionIcon
        variant="default"
        size="lg"
        radius="md"
        aria-label="Toggle color scheme"
        onClick={() => setColorScheme(dark ? 'light' : 'dark')}
      >
        {dark ? <IconSun size={18} stroke={1.6} /> : <IconMoon size={18} stroke={1.6} />}
      </ActionIcon>
    </Tooltip>
  );
}

function initials(name: string) {
  const parts = name.replace(/^sa:/, '').split(/[\s._@-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '?') + (parts[1]?.[0] ?? '')).toUpperCase();
}

function UserMenu() {
  const { me, loading, anonymous, admin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();
  const { data: info } = useSystemInfo();

  if (loading) return <Skeleton height={34} width={120} radius="md" />;
  if (anonymous || !me) {
    return (
      <Button
        leftSection={<IconLogin size={16} />}
        radius="md"
        onClick={() => navigate('/login?return=' + encodeURIComponent(location.pathname + location.search))}
      >
        Sign in
      </Button>
    );
  }

  const logout = async () => {
    if (info?.oidc.enabled) {
      // GET /auth/logout also ends the identity provider session.
      window.location.href = '/auth/logout';
      return;
    }
    await sessionLogout();
    navigate('/repositories');
    // Reset (not just clear) so mounted observers drop the signed-in data.
    await qc.resetQueries();
  };

  return (
    <Menu position="bottom-end" width={260} shadow="md" withinPortal>
      <Menu.Target>
        <UnstyledButton aria-label="User menu">
          <Group gap={8} wrap="nowrap">
            <Avatar size={32} radius="xl" color="blue">
              {initials(me.name)}
            </Avatar>
            <Box visibleFrom="sm" maw={160}>
              <Text size="sm" fw={500} truncate="end">
                {me.name}
              </Text>
            </Box>
            <IconChevronDown size={14} />
          </Group>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Box px="sm" py={6}>
          <Text size="sm" fw={600} truncate="end">
            {me.name}
          </Text>
          {me.email && (
            <Text size="xs" c="dimmed" truncate="end">
              {me.email}
            </Text>
          )}
          <Group gap={4} mt={6}>
            <Badge size="xs" variant="light" color="gray">
              {me.kind}
            </Badge>
            {admin && (
              <Badge size="xs" variant="light" color="grape">
                admin
              </Badge>
            )}
            {me.scopes.map((s) => (
              <Badge key={s} size="xs" variant="outline" color="gray">
                scope: {s}
              </Badge>
            ))}
          </Group>
          {me.groups.length > 0 && (
            <>
              <Text size="xs" c="dimmed" mt={8}>
                Groups
              </Text>
              <Group gap={4} mt={2}>
                {me.groups.slice(0, 12).map((g) => (
                  <Badge key={g} size="xs" variant="dot" color="blue" tt="none">
                    {g}
                  </Badge>
                ))}
                {me.groups.length > 12 && (
                  <Text size="xs" c="dimmed">
                    +{me.groups.length - 12} more
                  </Text>
                )}
              </Group>
            </>
          )}
        </Box>
        <Menu.Divider />
        <Menu.Item component={Link} to="/tokens" leftSection={<IconKey size={16} />}>
          API tokens
        </Menu.Item>
        <Menu.Item color="red" leftSection={<IconLogout size={16} />} onClick={logout}>
          Sign out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}

function NavSection({ title, items, onNavigate }: { title?: string; items: NavItem[]; onNavigate: () => void }) {
  const location = useLocation();
  return (
    <Box mb="sm">
      {title && (
        <Text size="xs" fw={700} c="dimmed" tt="uppercase" px="sm" mb={4} style={{ letterSpacing: 0.5 }}>
          {title}
        </Text>
      )}
      {items.map((it) => {
        const active = location.pathname === it.to || location.pathname.startsWith(it.to + '/');
        return (
          <NavLink
            key={it.to}
            component={Link}
            to={it.to}
            label={it.label}
            leftSection={<it.icon size={18} stroke={1.6} />}
            active={active}
            variant="light"
            onClick={onNavigate}
            style={{ borderRadius: 'var(--mantine-radius-md)' }}
          />
        );
      })}
    </Box>
  );
}

export function AppLayout({ children }: { children?: ReactNode }) {
  const [opened, { toggle, close }] = useDisclosure();
  const { admin, anonymous } = useAuth();
  const { data: info } = useSystemInfo();

  return (
    <AppShell
      header={{ height: 60 }}
      navbar={{ width: 240, breakpoint: 'sm', collapsed: { mobile: !opened } }}
      padding="lg"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="sm" wrap="nowrap">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <UnstyledButton component={Link} to="/repositories" aria-label="Entrepot home">
              <Logo />
            </UnstyledButton>
          </Group>
          <Group gap="xs" wrap="nowrap">
            <Tooltip label="REST API documentation" withArrow>
              <Button
                component="a"
                href="/api/docs"
                target="_blank"
                rel="noreferrer"
                variant="subtle"
                color="gray"
                radius="md"
                leftSection={<IconBook2 size={18} stroke={1.6} />}
                visibleFrom="xs"
              >
                API docs
              </Button>
            </Tooltip>
            <ColorSchemeToggle />
            <Divider orientation="vertical" mx={4} />
            <UserMenu />
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm">
        <AppShell.Section grow component={ScrollArea}>
          <NavSection title="Browse" items={browseNav} onNavigate={close} />
          {!anonymous && (
            <NavSection title="Account" items={[{ to: '/tokens', label: 'API tokens', icon: IconKey }]} onNavigate={close} />
          )}
          {admin && <NavSection title="Administration" items={adminNav} onNavigate={close} />}
          {admin && <NavSection title="Security scanning" items={securityNav} onNavigate={close} />}
        </AppShell.Section>
        <AppShell.Section>
          <Text size="xs" c="dimmed" px="sm">
            Entrepot {info?.version ?? ''}
          </Text>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <Box maw={1280} mx="auto">
          {children ?? <Outlet />}
        </Box>
      </AppShell.Main>
    </AppShell>
  );
}
