import { Button } from '@mantine/core';
import { IconMapOff } from '@tabler/icons-react';
import { Link } from 'react-router';
import { EmptyState } from '../components/states';

export function NotFoundPage() {
  return (
    <EmptyState
      icon={<IconMapOff size={28} stroke={1.5} />}
      title="Page not found"
      description="The page you are looking for does not exist."
      action={
        <Button component={Link} to="/repositories" variant="light">
          Go to repositories
        </Button>
      }
    />
  );
}
