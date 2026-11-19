import { useMe } from '../api/queries';

/** Convenience wrapper around GET /me. */
export function useAuth() {
  const me = useMe();
  const data = me.data;
  return {
    me: data,
    loading: me.isPending,
    anonymous: !data || data.kind === 'anonymous',
    admin: !!data?.admin,
  };
}
