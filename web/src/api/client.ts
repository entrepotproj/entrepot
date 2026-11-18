import createClient from 'openapi-fetch';
import type { components, paths } from './schema';

export type Schemas = components['schemas'];
export type Repository = Schemas['Repository'];
export type RepositoryInput = Schemas['RepositoryInput'];
export type RepositoryKind = Schemas['RepositoryKind'];
export type BlobStore = Schemas['BlobStore'];
export type BlobStoreInput = Schemas['BlobStoreInput'];
export type Asset = Schemas['Asset'];
export type BrowseEntry = Schemas['BrowseEntry'];
export type Component = Schemas['Component'];
export type ComponentDetail = Schemas['ComponentDetail'];
export type SystemInfo = Schemas['SystemInfo'];
export type Me = Schemas['Me'];
export type ApiToken = Schemas['ApiToken'];
export type ApiTokenInput = Schemas['ApiTokenInput'];
export type ApiTokenCreated = Schemas['ApiTokenCreated'];
export type User = Schemas['User'];
export type Role = Schemas['Role'];
export type RoleInput = Schemas['RoleInput'];
export type Action = Schemas['Action'];
export type RoleBinding = Schemas['RoleBinding'];
export type RoleBindingInput = Schemas['RoleBindingInput'];
export type SubjectType = Schemas['SubjectType'];
export type GitLabTrustPolicy = Schemas['GitLabTrustPolicy'];
export type GitLabTrustPolicyInput = Schemas['GitLabTrustPolicyInput'];
export type AuditEvent = Schemas['AuditEvent'];

/** Header required on state-changing requests authenticated by the session cookie. */
export const CSRF_HEADER = { 'X-Entrepot-CSRF': '1' } as const;

export const api = createClient<paths>({
  baseUrl: '/api/v1',
  credentials: 'same-origin',
  headers: CSRF_HEADER,
});

/** An error response from the API ({code, message}) or a network failure. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }

  get unauthorized() {
    return this.status === 401;
  }

  get forbidden() {
    return this.status === 403;
  }

  get notFound() {
    return this.status === 404;
  }
}

function toApiError(response: Response, error: unknown): ApiError {
  if (error && typeof error === 'object' && 'message' in error) {
    const e = error as { code?: string; message?: string };
    return new ApiError(response.status, e.code ?? String(response.status), e.message ?? response.statusText);
  }
  const text = typeof error === 'string' && error.trim() ? error.trim() : response.statusText || 'Request failed';
  return new ApiError(response.status, String(response.status), text);
}

type FetchResult<T> = { data?: T; error?: unknown; response: Response };

/**
 * Unwraps an openapi-fetch result: returns the data or throws an ApiError.
 * Use with endpoints that return a body (2xx with JSON).
 */
export async function unwrap<T>(p: Promise<FetchResult<T>>): Promise<T> {
  let res: FetchResult<T>;
  try {
    res = await p;
  } catch (e) {
    throw new ApiError(0, 'network', e instanceof Error ? e.message : 'Network error');
  }
  if (!res.response.ok || res.error !== undefined) {
    throw toApiError(res.response, res.error);
  }
  return res.data as T;
}

/** Like unwrap, for endpoints that return 204 No Content. */
export async function unwrapVoid(p: Promise<FetchResult<unknown>>): Promise<void> {
  await unwrap(p);
}

/** POST /auth/token-login: creates a browser session from an API or bootstrap token. */
export async function tokenLogin(token: string): Promise<void> {
  const res = await fetch('/auth/token-login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADER },
    body: JSON.stringify({ token }),
  });
  if (!res.ok) {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = undefined;
    }
    throw toApiError(res, body);
  }
}

/** POST /auth/logout: clears the session cookie without leaving the app. */
export async function sessionLogout(): Promise<void> {
  await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin', headers: CSRF_HEADER });
}

export function loginUrl(returnTo: string): string {
  return '/auth/login?return=' + encodeURIComponent(returnTo);
}
