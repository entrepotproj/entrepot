import { Center, Loader } from '@mantine/core';
import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { AppLayout } from './components/AppLayout';
import { RequireAdmin } from './components/RequireAdmin';
import { AssetPage } from './pages/AssetPage';
import { ComponentPage } from './pages/ComponentPage';
import { DashboardPage } from './pages/DashboardPage';
import { LoginPage } from './pages/LoginPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { RepositoriesPage } from './pages/RepositoriesPage';
import { RepositoryCreatePage } from './pages/RepositoryCreatePage';
import { RepositoryPage } from './pages/RepositoryPage';
import { SearchPage } from './pages/SearchPage';
import { TokensPage } from './pages/TokensPage';

// Admin pages are loaded on demand.
const BlobStoresPage = lazy(() => import('./pages/admin/BlobStoresPage'));
const RolesPage = lazy(() => import('./pages/admin/RolesPage'));
const GitLabPoliciesPage = lazy(() => import('./pages/admin/GitLabPoliciesPage'));
const ServiceAccountsPage = lazy(() => import('./pages/admin/ServiceAccountsPage'));
const UsersPage = lazy(() => import('./pages/admin/UsersPage'));
const AuditLogPage = lazy(() => import('./pages/admin/AuditLogPage'));
const ActivityLogPage = lazy(() => import('./pages/admin/ActivityLogPage'));
const ScannersPage = lazy(() => import('./pages/admin/ScannersPage'));
const WaiversPage = lazy(() => import('./pages/admin/WaiversPage'));
const ScanJobsPage = lazy(() => import('./pages/admin/ScanJobsPage'));
const CleanupPoliciesPage = lazy(() => import('./pages/admin/CleanupPoliciesPage'));
const RoutingRulesPage = lazy(() => import('./pages/admin/RoutingRulesPage'));

function PageLoader() {
  return (
    <Center py={80}>
      <Loader size="sm" />
    </Center>
  );
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <AppLayout>
            <Suspense fallback={<PageLoader />}>
              <AppRoutes />
            </Suspense>
          </AppLayout>
        }
        path="/*"
      />
    </Routes>
  );
}

function AppRoutes() {
  return (
    <Routes>
      <Route index element={<DashboardPage />} />
      <Route path="dashboard" element={<Navigate to="/" replace />} />
      <Route path="repositories" element={<RepositoriesPage />} />
      <Route
        path="repositories/new"
        element={
          <RequireAdmin>
            <RepositoryCreatePage />
          </RequireAdmin>
        }
      />
      <Route path="repositories/:name" element={<RepositoryPage />} />
      <Route path="repositories/:name/:tab" element={<RepositoryPage />} />
      <Route path="assets/:id" element={<AssetPage />} />
      <Route path="components/:id" element={<ComponentPage />} />
      <Route path="search" element={<SearchPage />} />
      <Route path="tokens" element={<TokensPage />} />
      <Route path="admin" element={<Navigate to="/admin/blob-stores" replace />} />
      <Route path="admin/blob-stores" element={<RequireAdmin><BlobStoresPage /></RequireAdmin>} />
      <Route path="admin/roles" element={<RequireAdmin><RolesPage /></RequireAdmin>} />
      <Route path="admin/gitlab" element={<RequireAdmin><GitLabPoliciesPage /></RequireAdmin>} />
      <Route path="admin/service-accounts" element={<RequireAdmin><ServiceAccountsPage /></RequireAdmin>} />
      <Route path="admin/service-accounts/:name" element={<RequireAdmin><ServiceAccountsPage /></RequireAdmin>} />
      <Route path="admin/users" element={<RequireAdmin><UsersPage /></RequireAdmin>} />
      <Route path="admin/activity" element={<RequireAdmin><ActivityLogPage /></RequireAdmin>} />
      <Route path="admin/audit" element={<RequireAdmin><AuditLogPage /></RequireAdmin>} />
      <Route path="admin/scanners" element={<RequireAdmin><ScannersPage /></RequireAdmin>} />
      <Route path="admin/waivers" element={<RequireAdmin><WaiversPage /></RequireAdmin>} />
      <Route path="admin/scan-jobs" element={<RequireAdmin><ScanJobsPage /></RequireAdmin>} />
      <Route path="admin/cleanup-policies" element={<RequireAdmin><CleanupPoliciesPage /></RequireAdmin>} />
      <Route path="admin/routing-rules" element={<RequireAdmin><RoutingRulesPage /></RequireAdmin>} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
