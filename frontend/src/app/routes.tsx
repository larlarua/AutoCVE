import type { ReactNode } from 'react';

import Account from '@/pages/Account';
import AdminDashboard from '@/pages/AdminDashboard';
import AgentAudit from '@/pages/AgentAudit';
import AuditSession from '@/pages/AuditSession';
import AuditTasks from '@/pages/AuditTasks';
import CheckmarxScan from '@/pages/CheckmarxScan';
import Dashboard from '@/pages/Dashboard';
import HomeCover from '@/pages/HomeCover';
import OneClickCVE from '@/pages/OneClickCVE';
import ProjectDetail from '@/pages/ProjectDetail';
import Projects from '@/pages/Projects';
import ReportTemplatesPage from '@/pages/ReportTemplatesPage';
import SkillsManager from '@/pages/SkillsManager';
import TaskDetail from '@/pages/TaskDetail';
import VulnerabilityManagement from '@/pages/VulnerabilityManagement';
import { internalBrandingEnabled } from '@/shared/config/branding';

export interface RouteConfig {
  name: string;
  labelKey: string;
  path: string;
  element: ReactNode;
  visible?: boolean;
}

// const enableCheckmarxScan = import.meta.env.VITE_ENABLE_CHECKMARX_SCAN === 'true';
const enableCheckmarxScan = false;
const routes: RouteConfig[] = [
  { name: '首页', labelKey: "routes.home", path: '/', element: <HomeCover />, visible: !internalBrandingEnabled },
  { name: 'Agent审计详情', labelKey: "routes.agentAuditDetail", path: '/agent-audit/:taskId', element: <AgentAudit />, visible: false },
  { name: '审计会话', labelKey: "routes.auditSession", path: '/audit-sessions/:sessionId', element: <AuditSession />, visible: false },
  { name: '仪表盘', labelKey: "routes.dashboard", path: '/dashboard', element: <Dashboard />, visible: true },
  { name: '项目管理', labelKey: "routes.projects", path: '/projects', element: <Projects />, visible: true },
  { name: '一键CVE', labelKey: "routes.oneClickCve", path: '/one-click-cve', element: <OneClickCVE />, visible: true },
  { name: '项目详情', labelKey: "routes.projectDetail", path: '/projects/:id', element: <ProjectDetail />, visible: false },
  { name: '审计任务', labelKey: "routes.auditTasks", path: '/audit-tasks', element: <AuditTasks />, visible: true },
  { name: '任务详情', labelKey: "routes.taskDetail", path: '/tasks/:id', element: <TaskDetail />, visible: false },
  { name: 'Skills管理', labelKey: "routes.skills", path: '/skills', element: <SkillsManager />, visible: true },
  { name: '报告模板', labelKey: "routes.reportTemplates", path: '/report-templates', element: <ReportTemplatesPage />, visible: false },
  { name: '漏洞管理', labelKey: "routes.vulnerabilities", path: '/vulnerabilities', element: <VulnerabilityManagement />, visible: true },
  ...(enableCheckmarxScan
    ? [{ name: 'Checkmarx扫描', labelKey: "routes.checkmarxScan", path: '/checkmarx-scan', element: <CheckmarxScan />, visible: true }]
    : []),
  { name: '系统设置', labelKey: "routes.settings", path: '/admin', element: <AdminDashboard />, visible: true },
  { name: '账号管理', labelKey: "routes.account", path: '/account', element: <Account />, visible: false },
];

export default routes;
