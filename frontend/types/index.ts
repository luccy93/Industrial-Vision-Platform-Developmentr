export type HealthState = {
  status: string;
  service?: string;
  env?: string;
  checks?: Record<string, { status: string } & Record<string, unknown>>;
};

export type NavItem = {
  href: string;
  label: string;
  note: string;
};

export const NAV_ITEMS: NavItem[] = [
  { href: "/", label: "Overview", note: "V01 foundation" },
  { href: "/dashboard", label: "Dashboard", note: "Shell — live views in later volumes" },
  { href: "/system", label: "System", note: "API / DB / Redis status" }
];
