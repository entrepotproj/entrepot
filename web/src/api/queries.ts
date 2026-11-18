import { useQuery } from '@tanstack/react-query';
import { api, ApiError, unwrap, type Me } from './client';

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
