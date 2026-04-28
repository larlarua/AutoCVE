import { Link } from "react-router-dom";
import { Loader2, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import type { ManagedVulnerability } from "@/shared/api/vulnerabilities";

function formatSeverity(value?: string | null) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical") return "严重";
  if (normalized === "high") return "高危";
  if (normalized === "medium") return "中危";
  if (normalized === "low") return "低危";
  if (normalized === "info") return "提示";
  return value || "未知";
}

function formatTime(value?: string | null) {
  if (!value) {
    return "--";
  }

  return new Date(value).toLocaleString("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function ReportSummaryCard({
  autoSyncManagedReports,
  onAutoSyncChange,
  syncActionDisabled,
  syncActionLabel: _syncActionLabel,
  onSyncLatestReport,
  hasLatestReport,
  latestReportSynced,
  managedVulnerabilities,
  managedVulnerabilitiesLoading,
}: {
  autoSyncManagedReports: boolean;
  onAutoSyncChange: (checked: boolean) => void;
  syncActionDisabled: boolean;
  syncActionLabel: string;
  onSyncLatestReport: () => void;
  hasLatestReport: boolean;
  latestReportSynced: boolean;
  managedVulnerabilities: ManagedVulnerability[];
  managedVulnerabilitiesLoading: boolean;
}) {
  const items = managedVulnerabilities.slice(0, 2);
  const actionLabel = !hasLatestReport ? "暂无报告" : latestReportSynced ? "已同步" : syncActionDisabled ? "同步中..." : "同步报告";

  return (
    <div className="rounded-[24px] border border-[rgba(177,200,185,.32)] bg-[linear-gradient(180deg,rgba(255,255,255,.98),rgba(241,247,243,.96))] p-4 shadow-[0_14px_28px_rgba(98,124,104,.08)]">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="flex h-9 w-9 items-center justify-center rounded-2xl border border-[rgba(177,200,185,.32)] bg-[rgba(237,245,239,.92)] text-[rgb(94,122,99)]">
            {latestReportSynced ? <ShieldCheck className="h-4 w-4" /> : <ShieldAlert className="h-4 w-4" />}
          </span>
          <div>
            <div className="text-sm font-semibold text-slate-900">报告同步</div>
            <div className="text-xs text-slate-500">
              {!hasLatestReport ? "暂无报告" : latestReportSynced ? "已同步" : "待同步"}
            </div>
          </div>
        </div>
        <Button
          type="button"
          size="sm"
          disabled={syncActionDisabled}
          onClick={onSyncLatestReport}
          className="h-9 rounded-full bg-[linear-gradient(135deg,#89A98D,#5E7A63)] px-4 text-white shadow-[0_10px_22px_rgba(94,122,99,.18)] hover:opacity-95 disabled:opacity-70"
        >
          <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
          {actionLabel}
        </Button>
      </div>

      <div className="mt-4 flex items-center justify-between rounded-[18px] border border-[rgba(177,200,185,.24)] bg-white/86 px-4 py-3">
        <span className="text-sm text-slate-700">自动同步</span>
        <Switch checked={autoSyncManagedReports} onCheckedChange={onAutoSyncChange} />
      </div>

      <div className="mt-4 space-y-3">
        {managedVulnerabilitiesLoading ? (
          <div className="flex items-center gap-2 rounded-[18px] border border-[rgba(177,200,185,.24)] bg-white/82 px-4 py-4 text-sm text-slate-500">
            <Loader2 className="h-4 w-4 animate-spin" />
            加载中...
          </div>
        ) : items.length === 0 ? (
          <div className="rounded-[18px] border border-dashed border-[rgba(177,200,185,.24)] bg-white/78 px-4 py-4 text-sm text-slate-500">
            暂无记录
          </div>
        ) : (
          items.map((item) => (
            <div key={item.id} className="rounded-[18px] border border-[rgba(177,200,185,.24)] bg-white/90 px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold text-slate-900">{item.vulnerability_name}</div>
                  <div className="mt-1 truncate text-xs text-slate-500">
                    {item.file_path || "未知文件"}
                    {item.line_start
                      ? `:${item.line_start}${item.line_end && item.line_end !== item.line_start ? `-${item.line_end}` : ""}`
                      : ""}
                  </div>
                </div>
                <Badge variant="outline" className="rounded-full border-[rgba(177,200,185,.34)] bg-[rgba(240,247,242,.9)]">
                  {formatSeverity(item.severity)}
                </Badge>
              </div>
              <div className="mt-2 text-xs text-slate-500">{formatTime(item.updated_at || item.created_at)}</div>
            </div>
          ))
        )}
      </div>

      <Link to="/vulnerabilities" className="mt-4 inline-flex text-xs font-semibold text-[rgb(94,122,99)] hover:underline">
        打开漏洞管理
      </Link>
    </div>
  );
}
