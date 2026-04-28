/**
 * Stats Panel Component
 * Dashboard-style statistics with premium visual design
 * Features: Animated progress, metric gauges, severity indicators
 * Enhanced visual effects with depth and polish
 */

import { memo } from "react";
import { Activity, FileCode, Repeat, Zap, Bug, Shield, AlertTriangle, TrendingUp, Clock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { StatsPanelProps } from "../types";

// Enhanced Circular progress component with glow effect
function CircularProgress({ value, size = 52, strokeWidth = 4, color = "primary" }: {
  value: number;
  size?: number;
  strokeWidth?: number;
  color?: string;
}) {
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (value / 100) * circumference;

  const colorMap: Record<string, { stroke: string; glow: string }> = {
    primary: { stroke: '#FF6B2C', glow: 'rgba(255,107,44,0.4)' },
    emerald: { stroke: '#34d399', glow: 'rgba(52,211,153,0.4)' },
    rose: { stroke: '#fb7185', glow: 'rgba(251,113,133,0.4)' },
    amber: { stroke: '#fbbf24', glow: 'rgba(251,191,36,0.4)' },
  };

  const colors = colorMap[color] || colorMap.primary;

  return (
    <svg width={size} height={size} className="transform -rotate-90">
      {/* Background circle with subtle gradient */}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke="rgba(255,255,255,0.08)"
        strokeWidth={strokeWidth}
      />
      {/* Glow effect circle */}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={colors.stroke}
        strokeWidth={strokeWidth + 4}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        className="transition-all duration-700 ease-out opacity-20 blur-sm"
      />
      {/* Progress circle */}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={colors.stroke}
        strokeWidth={strokeWidth}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        className="transition-all duration-700 ease-out"
        style={{
          filter: `drop-shadow(0 0 8px ${colors.glow})`,
        }}
      />
    </svg>
  );
}

// Enhanced Metric card component with premium styling
function MetricCard({ icon, label, value, suffix = "", colorClass = "text-muted-foreground", bgClass = "" }: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  suffix?: string;
  colorClass?: string;
  bgClass?: string;
}) {
  return (
    <div className={`
      group relative flex items-center gap-3 p-3.5 rounded-lg
      bg-card/80 border border-border/50 backdrop-blur-sm
      hover:bg-card hover:border-border/80 hover:shadow-md
      transition-all duration-300
      ${bgClass}
    `}>
      {/* Subtle gradient overlay on hover */}
      <div className="absolute inset-0 rounded-lg bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />

      <div className={`relative z-10 p-2 rounded-md bg-muted/50 border border-border/50 ${colorClass} transition-transform duration-300 group-hover:scale-105`}>
        {icon}
      </div>
      <div className="flex-1 min-w-0 relative z-10">
        <div className="text-xs text-muted-foreground uppercase tracking-wider truncate font-medium mb-0.5">{label}</div>
        <div className="text-lg text-foreground font-mono font-bold leading-tight">
          {value}<span className="text-muted-foreground text-sm ml-0.5">{suffix}</span>
        </div>
      </div>
    </div>
  );
}

export const StatsPanel = memo(function StatsPanel({ task, findings }: StatsPanelProps) {
  if (!task) return null;

  // 🔥 Use task's reliable statistics instead of computing from findings array
  // This ensures consistency even when findings array is empty or not loaded
  const severityCounts = {
    critical: task.critical_count || 0,
    high: task.high_count || 0,
    medium: task.medium_count || 0,
    low: task.low_count || 0,
  };
  const finalizedFindings = task.finalized_findings_count ?? task.findings_count ?? 0;
  const recoveredCandidates = task.recovered_candidates_count ?? 0;
  const totalFindings = finalizedFindings;
  const progressPercent = task.progress_percentage || 0;
  const topFindings = [...(findings || [])]
    .sort((a, b) => {
      const statusRank = { confirmed: 0, candidate: 1, false_positive: 2 } as const;
      const severityRank = { critical: 0, high: 1, medium: 2, low: 3 } as const;
      const aStatus = statusRank[(a.report_status || a.verdict || "candidate") as keyof typeof statusRank] ?? 3;
      const bStatus = statusRank[(b.report_status || b.verdict || "candidate") as keyof typeof statusRank] ?? 3;
      if (aStatus !== bStatus) return aStatus - bStatus;
      const aSeverity = severityRank[(a.severity || "low") as keyof typeof severityRank] ?? 4;
      const bSeverity = severityRank[(b.severity || "low") as keyof typeof severityRank] ?? 4;
      return aSeverity - bSeverity;
    })
    .slice(0, 3);

  // Determine score color
  const getScoreColor = (score: number) => {
    if (score >= 80) return 'emerald';
    if (score >= 60) return 'amber';
    return 'rose';
  };

  const outcomeConfig = {
    finalized: {
      label: 'Finalized',
      badgeClass: 'bg-emerald-500/15 text-emerald-700 border border-emerald-500/30',
      description: 'Runtime ended with explicit finalized findings.',
    },
    recovered_only: {
      label: 'Recovered Only',
      badgeClass: 'bg-sky-500/15 text-sky-700 border border-sky-500/30',
      description: 'Only transcript-recovered candidates are available.',
    },
    incomplete: {
      label: 'Incomplete',
      badgeClass: 'bg-amber-500/15 text-amber-700 border border-amber-500/30',
      description: 'Runtime stopped without a terminal action or finalized findings.',
    },
    none: {
      label: 'No Findings',
      badgeClass: 'bg-slate-500/15 text-slate-700 border border-slate-500/30',
      description: 'No finalized findings or recovered candidates are currently available.',
    },
  }[task.finding_outcome || 'none'];

  return (
    <div className="space-y-3">
      {/* Progress Section with enhanced styling */}
      <div className="p-4 rounded-lg border border-border/50 bg-card/80 backdrop-blur-sm relative overflow-hidden">
        {/* Background gradient */}
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />

        <div className="relative z-10">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-md bg-primary/15 border border-primary/30">
                <Activity className="w-4 h-4 text-primary" />
              </div>
              <span className="text-sm text-foreground uppercase tracking-wider font-semibold">Progress</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-lg text-primary font-mono font-bold">{progressPercent.toFixed(0)}</span>
              <span className="text-sm text-muted-foreground">%</span>
            </div>
          </div>

          {/* Enhanced Progress bar */}
          <div className="relative h-3 bg-muted/50 rounded-full overflow-hidden border border-border/30">
            <div
              className="absolute inset-y-0 left-0 bg-gradient-to-r from-primary via-primary to-primary/80 rounded-full transition-all duration-700 ease-out"
              style={{ width: `${progressPercent}%` }}
            />
            {/* Animated shine effect */}
            <div
              className="absolute inset-y-0 left-0 bg-gradient-to-r from-transparent via-white/30 to-transparent rounded-full"
              style={{
                width: `${progressPercent}%`,
                animation: 'shine 2s ease-in-out infinite',
              }}
            />
            {/* Glow effect */}
            <div
              className="absolute inset-y-0 left-0 rounded-full blur-sm opacity-50"
              style={{
                width: `${progressPercent}%`,
                background: 'linear-gradient(to right, #FF6B2C, #FF6B2C)',
              }}
            />
          </div>

          {/* File progress with enhanced styling */}
          <div className="flex items-center justify-between mt-4 text-sm">
            <div className="flex items-center gap-2 text-muted-foreground">
              <FileCode className="w-4 h-4" />
              <span className="font-medium">Files scanned</span>
            </div>
            <span className="text-foreground font-mono font-bold">
              {task.analyzed_files}<span className="text-muted-foreground font-normal"> / {task.total_files}</span>
            </span>
          </div>
          {/* Files with findings */}
          {task.files_with_findings > 0 && (
            <div className="flex items-center justify-between mt-2 text-sm">
              <div className="flex items-center gap-2 text-muted-foreground">
                <AlertTriangle className="w-4 h-4 text-rose-500" />
                <span className="font-medium">Files with findings</span>
              </div>
              <span className="text-rose-500 font-mono font-bold">
                {task.files_with_findings}
              </span>
            </div>
          )}
        </div>
      </div>

      <div className="rounded-lg border border-border/50 bg-card/80 p-4 backdrop-blur-sm">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="rounded-md border border-border/50 bg-muted/40 p-1.5">
              <Shield className="h-4 w-4 text-primary" />
            </div>
            <div>
              <div className="text-sm font-semibold text-foreground">Finding Outcome</div>
              <div className="text-xs text-muted-foreground">{outcomeConfig.description}</div>
            </div>
          </div>
          <Badge className={outcomeConfig.badgeClass}>{outcomeConfig.label}</Badge>
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2.5">
          <MetricCard
            icon={<Bug className="w-4 h-4" />}
            label="Finalized"
            value={finalizedFindings}
            colorClass={finalizedFindings > 0 ? "text-rose-500" : "text-muted-foreground"}
            bgClass={finalizedFindings > 0 ? "border-rose-500/20" : ""}
          />
          <MetricCard
            icon={<AlertTriangle className="w-4 h-4" />}
            label="Recovered"
            value={recoveredCandidates}
            colorClass={recoveredCandidates > 0 ? "text-sky-500" : "text-muted-foreground"}
            bgClass={recoveredCandidates > 0 ? "border-sky-500/20" : ""}
          />
        </div>
        {task.runtime_completion_mode ? (
          <div className="mt-3 text-xs text-muted-foreground">
            Runtime completion mode: <span className="font-mono text-foreground">{task.runtime_completion_mode}</span>
            {task.handoff_ready ? <span className="ml-2 text-emerald-600">handoff ready</span> : null}
          </div>
        ) : null}
      </div>

      {/* Metrics Grid with enhanced styling */}
      <div className="grid grid-cols-2 gap-2.5">
        <MetricCard
          icon={<Repeat className="w-4 h-4" />}
          label="Iterations"
          value={task.total_iterations || 0}
          colorClass="text-teal-500"
        />
        <MetricCard
          icon={<Zap className="w-4 h-4" />}
          label="Tool Calls"
          value={task.tool_calls_count || 0}
          colorClass="text-amber-500"
        />
        <MetricCard
          icon={<TrendingUp className="w-4 h-4" />}
          label="Tokens"
          value={((task.tokens_used || 0) / 1000).toFixed(1)}
          suffix="k"
          colorClass="text-violet-500"
        />
        <MetricCard
          icon={<Bug className="w-4 h-4" />}
          label="Persisted Findings"
          value={totalFindings}
          colorClass={totalFindings > 0 ? "text-rose-500" : "text-muted-foreground"}
          bgClass={totalFindings > 0 ? "border-rose-500/20" : ""}
        />
      </div>

      {/* Findings breakdown with enhanced styling */}
      {totalFindings > 0 && (
        <div className="p-4 rounded-lg border border-rose-500/20 bg-card/80 backdrop-blur-sm relative overflow-hidden">
          {/* Background gradient */}
          <div className="absolute inset-0 bg-gradient-to-br from-rose-500/5 to-transparent pointer-events-none" />

          <div className="relative z-10">
            <div className="flex items-center gap-2.5 mb-3">
              <div className="p-1.5 rounded-md bg-rose-500/15 border border-rose-500/30">
                <AlertTriangle className="w-4 h-4 text-rose-500" />
              </div>
              <span className="text-sm text-foreground uppercase tracking-wider font-semibold">Severity Breakdown</span>
            </div>

            <div className="flex flex-wrap gap-2">
              {severityCounts.critical > 0 && (
                <Badge className="bg-rose-500/20 text-rose-600 dark:text-rose-300 border border-rose-500/40 text-xs font-mono font-bold px-2.5 py-1 shadow-[0_0_10px_rgba(244,63,94,0.15)]">
                  CRITICAL: {severityCounts.critical}
                </Badge>
              )}
              {severityCounts.high > 0 && (
                <Badge className="bg-orange-500/20 text-orange-600 dark:text-orange-300 border border-orange-500/40 text-xs font-mono font-bold px-2.5 py-1 shadow-[0_0_10px_rgba(249,115,22,0.15)]">
                  HIGH: {severityCounts.high}
                </Badge>
              )}
              {severityCounts.medium > 0 && (
                <Badge className="bg-amber-500/20 text-amber-600 dark:text-amber-300 border border-amber-500/40 text-xs font-mono font-bold px-2.5 py-1 shadow-[0_0_10px_rgba(245,158,11,0.15)]">
                  MEDIUM: {severityCounts.medium}
                </Badge>
              )}
              {severityCounts.low > 0 && (
                <Badge className="bg-sky-500/20 text-sky-600 dark:text-sky-300 border border-sky-500/40 text-xs font-mono font-bold px-2.5 py-1 shadow-[0_0_10px_rgba(14,165,233,0.15)]">
                  LOW: {severityCounts.low}
                </Badge>
              )}
            </div>
          </div>
        </div>
      )}

      {topFindings.length > 0 && (
        <div className="p-4 rounded-lg border border-primary/20 bg-card/80 backdrop-blur-sm relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
          <div className="relative z-10">
            <div className="flex items-center gap-2.5 mb-3">
              <div className="p-1.5 rounded-md bg-primary/15 border border-primary/30">
                <Bug className="w-4 h-4 text-primary" />
              </div>
              <span className="text-sm text-foreground uppercase tracking-wider font-semibold">Finalized Findings Preview</span>
            </div>
            <div className="space-y-2.5">
              {topFindings.map((finding) => {
                const reportStatus = finding.report_status || finding.verdict || (finding.is_verified ? "confirmed" : "candidate");
                return (
                  <div key={finding.id} className="rounded-lg border border-border/60 bg-white/55 px-3 py-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-sm font-semibold text-foreground leading-snug">{finding.title}</div>
                      <Badge className={`text-[10px] font-mono uppercase ${
                        reportStatus === "confirmed"
                          ? "bg-emerald-500/15 text-emerald-600 border border-emerald-500/30"
                          : reportStatus === "false_positive"
                            ? "bg-slate-500/15 text-slate-600 border border-slate-500/30"
                            : "bg-amber-500/15 text-amber-700 border border-amber-500/30"
                      }`}>
                        {reportStatus}
                      </Badge>
                    </div>
                    <div className="mt-1 text-[11px] font-mono text-muted-foreground">
                      {finding.severity?.toUpperCase()} · {finding.vulnerability_type}
                    </div>
                    {finding.file_path && (
                      <div className="mt-1 text-xs text-muted-foreground break-all">
                        {finding.file_path}{finding.line_start ? `:${finding.line_start}` : ""}
                      </div>
                    )}
                    {(finding.source || finding.sink) && (
                      <div className="mt-2 space-y-1 text-xs text-muted-foreground">
                        {finding.source && <div><span className="text-foreground/80">Source:</span> {finding.source}</div>}
                        {finding.sink && <div><span className="text-foreground/80">Sink:</span> {finding.sink}</div>}
                      </div>
                    )}
                    {finding.impact && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        <span className="text-foreground/80">Impact:</span> {finding.impact}
                      </div>
                    )}
                    {finding.exploit_chain && finding.exploit_chain.length > 0 && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        <span className="text-foreground/80">Exploit Chain:</span>{" "}
                        {finding.exploit_chain
                          .slice(0, 2)
                          .map((step) => step.location || step.description || `step ${step.step ?? "?"}`)
                          .join(" -> ")}
                        {finding.exploit_chain.length > 2 ? " -> ..." : ""}
                      </div>
                    )}
                    {finding.poc?.payload && (
                      <div className="mt-2 text-xs text-muted-foreground break-all">
                        <span className="text-foreground/80">PoC:</span> {finding.poc.payload}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Security Score with enhanced styling */}
      {task.security_score !== null && task.security_score !== undefined && (
        <div className="p-4 rounded-lg border border-emerald-500/20 bg-card/80 backdrop-blur-sm relative overflow-hidden">
          {/* Background gradient based on score */}
          <div className={`absolute inset-0 bg-gradient-to-br pointer-events-none ${
            task.security_score >= 80 ? 'from-emerald-500/5' :
            task.security_score >= 60 ? 'from-amber-500/5' :
            'from-rose-500/5'
          } to-transparent`} />

          <div className="relative z-10 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className={`p-1.5 rounded-md border ${
                task.security_score >= 80 ? 'bg-emerald-500/15 border-emerald-500/30' :
                task.security_score >= 60 ? 'bg-amber-500/15 border-amber-500/30' :
                'bg-rose-500/15 border-rose-500/30'
              }`}>
                <Shield className={`w-4 h-4 ${
                  task.security_score >= 80 ? 'text-emerald-500' :
                  task.security_score >= 60 ? 'text-amber-500' :
                  'text-rose-500'
                }`} />
              </div>
              <div>
                <span className="text-sm text-foreground uppercase tracking-wider font-semibold block">Security Score</span>
                <span className="text-xs text-muted-foreground">
                  {task.security_score >= 80 ? 'Excellent' :
                   task.security_score >= 60 ? 'Good' :
                   'Needs Attention'}
                </span>
              </div>
            </div>
            <div className="relative">
              <CircularProgress
                value={task.security_score}
                size={56}
                strokeWidth={4}
                color={getScoreColor(task.security_score)}
              />
              <div className="absolute inset-0 flex items-center justify-center">
                <span className={`text-base font-bold font-mono ${
                  task.security_score >= 80 ? 'text-emerald-500' :
                  task.security_score >= 60 ? 'text-amber-500' :
                  'text-rose-500'
                }`}>
                  {task.security_score.toFixed(0)}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Inline animation */}
      <style>{`
        @keyframes shine {
          0% { transform: translateX(-100%); }
          50% { transform: translateX(100%); }
          100% { transform: translateX(100%); }
        }
      `}</style>
    </div>
  );
});

export default StatsPanel;
