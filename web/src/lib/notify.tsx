import { notifications } from '@mantine/notifications';
import { IconAlertTriangle, IconCheck, IconLock } from '@tabler/icons-react';
import { ApiError } from '../api/client';

export function notifySuccess(message: string, title?: string) {
  notifications.show({ color: 'teal', title, message, icon: <IconCheck size={18} /> });
}

export function describeError(err: unknown): { title: string; message: string } {
  if (err instanceof ApiError) {
    if (err.unauthorized) return { title: 'Sign in required', message: 'Your session has ended or you are not signed in.' };
    if (err.forbidden) return { title: 'Not permitted', message: err.message || 'You are not permitted to do this.' };
    if (err.status === 0) return { title: 'Network error', message: err.message };
    if (err.notImplemented) {
      return { title: 'Not available yet', message: "This feature isn't available on this server yet." };
    }
    return { title: errorTitle(err), message: err.message };
  }
  return { title: 'Error', message: err instanceof Error ? err.message : String(err) };
}

function errorTitle(err: ApiError): string {
  switch (err.code) {
    case 'conflict':
      return 'Conflict';
    case 'in_use':
      return 'Still in use';
    case 'quarantined':
      return 'Quarantined';
    case 'not_found':
      return 'Not found';
    case 'bad_request':
    case 'invalid':
      return 'Invalid request';
    default:
      if (err.status === 409) return 'Conflict';
      return err.status >= 500 ? 'Server error' : 'Request failed';
  }
}

export function notifyError(err: unknown) {
  const { title, message } = describeError(err);
  const locked = err instanceof ApiError && (err.unauthorized || err.forbidden);
  notifications.show({
    color: locked ? 'orange' : 'red',
    title,
    message,
    icon: locked ? <IconLock size={18} /> : <IconAlertTriangle size={18} />,
    autoClose: 8000,
  });
}
