export type DataRow = Record<string, unknown> & {
  id: string;
};
export interface Page<T = DataRow> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}
export interface User {
  id: string;
  email: string;
  role: 'admin' | 'viewer';
}
export interface DashboardData {
  counts: {
    projects: number;
    images: number;
    last_scan: string | null;
    stale_images: number;
    fixes: number;
    updates: number;
  };
  severity: {
    severity: string;
    count: number;
  }[];
  trend: {
    date: string;
    count: number;
    scans: number;
  }[];
  integrations: DataRow[];
  by_project: {
    name: string;
    count: number;
  }[];
  fixes: {
    date: string;
    count: number;
  }[];
}
