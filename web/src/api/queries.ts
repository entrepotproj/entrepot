import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api, ApiError, unwrap, type ComponentScans, type Me, type UsageRange } from './client';

export const qk = {
  systemInfo: ['system-info'] as const,
  me: ['me'] as const,
  repositories: ['repositories'] as const,
  repository: (name: string) => ['repositories', name] as const,
  blobStores: ['blob-stores'] as const,
  roles: ['roles'] as const,
  roleBindings: ['role-bindings'] as const,
  gitlabPolicies: ['gitlab-policies'] as const,
  serviceAccounts: ['service-accounts'] as const,
  serviceAccountTokens: (name: string) => ['service-accounts', name, 'tokens'] as const,
  users: ['users'] as const,
  tokens: ['tokens'] as const,
};

export function useSystemInfo() {
  return useQuery({
    queryKey: qk.systemInfo,
    queryFn: () => unwrap(api.GET('/system/info')),
    staleTime: 5 * 60_000,
  });
}

const anonymous: Me = { kind: 'anonymous', name: 'anonymous', groups: [], policies: [], scopes: [], admin: false };

/** The calling principal; resolves to an anonymous principal on 401. */
export function useMe() {
  return useQuery({
    queryKey: qk.me,
    queryFn: async () => {
      try {
        return await unwrap(api.GET('/me'));
      } catch (e) {
        if (e instanceof ApiError && e.unauthorized) return anonymous;
        throw e;
      }
    },
    staleTime: 60_000,
  });
}

export function useRepositories() {
  return useQuery({
    queryKey: qk.repositories,
    queryFn: () => unwrap(api.GET('/repositories')),
  });
}

export function useRepository(name: string) {
  return useQuery({
    queryKey: qk.repository(name),
    queryFn: () => unwrap(api.GET('/repositories/{name}', { params: { path: { name } } })),
    enabled: !!name,
  });
}

export function useBlobStores(enabled = true) {
  return useQuery({
    queryKey: qk.blobStores,
    queryFn: () => unwrap(api.GET('/blob-stores')),
    enabled,
  });
}

export function useRoles(enabled = true) {
  return useQuery({ queryKey: qk.roles, queryFn: () => unwrap(api.GET('/roles')), enabled });
}

export function useGitLabPolicies(enabled = true) {
  return useQuery({
    queryKey: qk.gitlabPolicies,
    queryFn: () => unwrap(api.GET('/gitlab-trust-policies')),
    enabled,
  });
}

// ---- Phase 2: scanning, cleanup, routing, signing ----

export const qk2 = {
  scanners: ['scanners'] as const,
  waivers: ['waivers'] as const,
  scanJobs: (status?: string) => ['scan-jobs', status ?? 'all'] as const,
  cleanupPolicies: ['cleanup-policies'] as const,
  routingRules: ['routing-rules'] as const,
  signingKey: (repo: string) => ['signing-key', repo] as const,
  componentScans: (id: string) => ['component-scans', id] as const,
};

export function useScanners(enabled = true) {
  return useQuery({ queryKey: qk2.scanners, queryFn: () => unwrap(api.GET('/scanners')), enabled });
}

export function useWaivers(enabled = true) {
  return useQuery({ queryKey: qk2.waivers, queryFn: () => unwrap(api.GET('/waivers')), enabled });
}

export function useCleanupPolicies(enabled = true) {
  return useQuery({ queryKey: qk2.cleanupPolicies, queryFn: () => unwrap(api.GET('/cleanup-policies')), enabled });
}

export function useRoutingRules(enabled = true) {
  return useQuery({ queryKey: qk2.routingRules, queryFn: () => unwrap(api.GET('/routing-rules')), enabled });
}

export function useSigningKey(repo: string, enabled = true) {
  return useQuery({
    queryKey: qk2.signingKey(repo),
    queryFn: () => unwrap(api.GET('/repositories/{name}/signing-key', { params: { path: { name: repo } } })),
    enabled: enabled && !!repo,
  });
}

export function useComponentScans(
  id: string,
  refetchInterval?: number | false | ((query: { state: { data?: ComponentScans } }) => number | false),
) {
  return useQuery({
    queryKey: qk2.componentScans(id),
    queryFn: () => unwrap(api.GET('/components/{id}/scans', { params: { path: { id } } })),
    enabled: !!id,
    refetchInterval,
  });
}

// ---- Usage metrics ----

/** Dashboard refresh period; TanStack Query pauses interval refetches while the tab is hidden. */
export const USAGE_REFRESH_MS = 30_000;

export function useMetricsOverview(range: UsageRange, enabled = true) {
  return useQuery({
    queryKey: ['metrics-overview', range],
    queryFn: () => unwrap(api.GET('/metrics/overview', { params: { query: { range } } })),
    refetchInterval: USAGE_REFRESH_MS,
    placeholderData: keepPreviousData,
    enabled,
  });
}

export function useRepositoryMetrics(name: string, range: UsageRange) {
  return useQuery({
    queryKey: ['repository-metrics', name, range],
    queryFn: () =>
      unwrap(api.GET('/repositories/{name}/metrics', { params: { path: { name }, query: { range } } })),
    refetchInterval: USAGE_REFRESH_MS,
    // Keep the previous range's data while switching ranges, but never show another repository's.
    placeholderData: (prev, prevQuery) => (prevQuery?.queryKey[1] === name ? prev : undefined),
    enabled: !!name,
  });
}
