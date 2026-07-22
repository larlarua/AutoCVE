import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  BookOpen,
  Bot,
  ChevronLeft,
  ChevronRight,
  FileText,
  FolderGit2,
  WandSparkles,
  LayoutDashboard,
  ListTodo,
  Menu,
  ScanSearch,
  Settings,
  ShieldAlert,
  UserCircle,
  X,
} from 'lucide-react';

import routes from '@/app/routes';
import { Button } from '@/components/ui/button';
import { defaultLandingPath, productName } from '@/shared/config/branding';
import { appVersionLabel } from '@/shared/config/version';

const routeIcons: Record<string, ReactNode> = {
  '/': <Bot className="h-[18px] w-[18px]" />,
  '/dashboard': <LayoutDashboard className="h-[18px] w-[18px]" />,
  '/projects': <FolderGit2 className="h-[18px] w-[18px]" />,
  '/one-click-cve': <WandSparkles className="h-[18px] w-[18px]" />,
  '/audit-tasks': <ListTodo className="h-[18px] w-[18px]" />,
  '/skills': <BookOpen className="h-[18px] w-[18px]" />,
  '/report-templates': <FileText className="h-[18px] w-[18px]" />,
  '/vulnerabilities': <ShieldAlert className="h-[18px] w-[18px]" />,
  '/checkmarx-scan': <ScanSearch className="h-[18px] w-[18px]" />,
  '/admin': <Settings className="h-[18px] w-[18px]" />,
};

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
}

export default function Sidebar({ collapsed, setCollapsed }: SidebarProps) {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  const visibleRoutes = useMemo(
    () => routes.filter((route) => route.visible !== false),
    []
  );

  return (
    <>
      <Button
        variant="ghost"
        size="icon"
        className="fixed left-4 top-4 z-50 rounded-2xl border border-white/70 bg-white/90 text-slate-700 shadow-[0_18px_35px_rgba(89,97,110,0.12)] backdrop-blur md:hidden"
        onClick={() => setMobileOpen((value) => !value)}
      >
        {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
      </Button>

      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-slate-900/18 backdrop-blur-sm md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={`fixed left-0 top-0 z-40 h-screen px-4 py-4 transition-all duration-300 ease-in-out ${collapsed ? 'w-[104px]' : 'w-[296px]'} ${mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}`}
      >
        <div className="relative flex h-full flex-col overflow-hidden rounded-[34px] border border-white/65 bg-white/82 shadow-[0_28px_70px_rgba(89,97,110,0.15)] backdrop-blur-xl">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(255,255,255,0.86),transparent_32%),linear-gradient(180deg,rgba(248,249,248,0.94),rgba(241,243,244,0.96))]" />

          <div className={`relative flex h-20 flex-shrink-0 items-center ${collapsed ? 'justify-center px-3' : 'justify-between px-5'} border-b border-slate-200/70`}>
            <Link
              to={defaultLandingPath}
              className={`group flex items-center gap-3 ${collapsed ? 'justify-center' : ''}`}
              onClick={() => setMobileOpen(false)}
            >
              <img src="/autocve_icon.svg" alt={productName} className="h-12 w-12 object-contain" />
              {!collapsed && (
                <div className="min-w-0">
                  <div className="text-[1.35rem] font-semibold tracking-[-0.03em] text-slate-900">{productName}</div>
                </div>
              )}
            </Link>

            {!collapsed && (
              <button
                className="hidden h-10 w-10 items-center justify-center rounded-2xl border border-slate-200/90 bg-white/70 text-slate-500 transition hover:border-[hsl(var(--primary)/0.45)] hover:text-[hsl(var(--primary))] md:flex"
                onClick={() => setCollapsed(true)}
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
            )}

            {collapsed && (
              <button
                className="absolute -right-2 top-1/2 hidden h-8 w-8 -translate-y-1/2 items-center justify-center rounded-full border border-slate-200/90 bg-white text-slate-500 shadow-sm transition hover:border-[hsl(var(--primary)/0.45)] hover:text-[hsl(var(--primary))] md:flex"
                onClick={() => setCollapsed(false)}
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            )}
          </div>

          <div className="relative flex-1 overflow-hidden px-3 py-4">
            <nav className="flex h-full flex-col gap-1 overflow-y-auto custom-scrollbar pr-1">
              {visibleRoutes.map((route) => {
                const isActive = location.pathname === route.path;
                const routeLabel = route.name;
                return (
                  <Link
                    key={route.path}
                    to={route.path}
                    title={collapsed ? routeLabel : undefined}
                    onClick={() => setMobileOpen(false)}
                    className={`group flex items-center gap-3 rounded-[20px] px-3 py-3 transition-all duration-200 ${isActive ? 'bg-[rgba(219,233,223,0.95)] text-slate-900 shadow-[0_12px_22px_rgba(111,167,132,0.14)]' : 'text-slate-500 hover:bg-white/70 hover:text-slate-900'}`}
                  >
                    <span className={`flex h-10 w-10 items-center justify-center rounded-2xl border transition-all ${isActive ? 'border-[rgba(111,167,132,0.24)] bg-white/80 text-[hsl(var(--primary))]' : 'border-transparent bg-slate-100/80 text-slate-500 group-hover:border-slate-200/80 group-hover:bg-white'}`}>
                      {routeIcons[route.path] || <LayoutDashboard className="h-[18px] w-[18px]" />}
                    </span>
                    {!collapsed && (
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-semibold">{routeLabel}</div>
                      </div>
                    )}
                  </Link>
                );
              })}
            </nav>
          </div>

          <div className="relative flex-shrink-0 border-t border-slate-200/70 p-4">
            <Link
              to="/account"
              className="group flex items-center gap-3 rounded-[22px] bg-[#f8f9f8] px-3 py-3 transition hover:bg-white"
            >
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-slate-200/80 bg-white text-slate-500">
                <UserCircle className="h-5 w-5" />
              </div>
              {!collapsed && (
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-semibold text-slate-900">账号管理</div>
                  <div className="text-xs text-slate-500">Profile & settings</div>
                </div>
              )}
            </Link>

            {!collapsed && (
              <div className="mt-3 flex items-center justify-between px-1 text-xs text-slate-400">
                <span>{appVersionLabel}</span>
                <span className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-emerald-400" />
                  Online
                </span>
              </div>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}

