import { memo } from "react";
import { AlertTriangle, CheckCircle2, FileCode, Link2, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { AgentFinding, AgentTask, RecoveredCandidate } from "@/shared/api/agentTasks";

type FinalReportPanelProps = {
  task: AgentTask | null;
  findings: AgentFinding[];
  recoveredCandidates?: RecoveredCandidate[];
};

type ReportItem =
  | (AgentFinding & { __kind: "finding" })
  | (RecoveredCandidate & { __kind: "recovered_candidate" });

const statusRank: Record<string, number> = {
  confirmed: 0,
  candidate: 1,
  recovered_candidate: 2,
  false_positive: 3,
};

const severityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function normalizeStatus(item: ReportItem): string {
  if (item.__kind === "recovered_candidate") {
    return item.report_status || item.verdict || "recovered_candidate";
  }
  return item.report_status || item.verdict || (item.is_verified ? "confirmed" : "candidate");
}

function statusBadgeClass(status: string): string {
  if (status === "confirmed") {
    return "bg-emerald-500/15 text-emerald-700 border border-emerald-500/30";
  }
  if (status === "recovered_candidate") {
    return "bg-sky-500/15 text-sky-700 border border-sky-500/30";
  }
  if (status === "false_positive") {
    return "bg-slate-500/15 text-slate-700 border border-slate-500/30";
  }
  return "bg-amber-500/15 text-amber-700 border border-amber-500/30";
}

function hasConfidence(item: ReportItem): item is AgentFinding & { __kind: "finding" } {
  return item.__kind === "finding";
}

function hasMeaningfulPoc(poc: AgentFinding["poc"]): boolean {
  if (!poc) {
    return false;
  }
  if (poc.description?.trim() || poc.payload?.trim()) {
    return true;
  }
  return Boolean(
    poc.steps?.some((step) =>
      Boolean(step.action?.trim() || step.request?.trim() || step.expected_response?.trim()),
    ),
  );
}

export const FinalReportPanel = memo(function FinalReportPanel({
  task,
  findings,
  recoveredCandidates = [],
}: FinalReportPanelProps) {
  if (!task) {
    return null;
  }

  const isRecoveredOnly = task.finding_outcome === "recovered_only";
  const reportItems: ReportItem[] = isRecoveredOnly
    ? recoveredCandidates.map((candidate) => ({ ...candidate, __kind: "recovered_candidate" as const }))
    : findings.map((finding) => ({ ...finding, __kind: "finding" as const }));

  if (!reportItems.length) {
    return null;
  }

  const orderedFindings = [...reportItems].sort((a, b) => {
    const aStatus = statusRank[normalizeStatus(a)] ?? 9;
    const bStatus = statusRank[normalizeStatus(b)] ?? 9;
    if (aStatus !== bStatus) return aStatus - bStatus;
    const aSeverity = severityRank[a.severity || "info"] ?? 9;
    const bSeverity = severityRank[b.severity || "info"] ?? 9;
    return aSeverity - bSeverity;
  });

  return (
    <section className="mt-3 overflow-hidden rounded-[22px] border border-border/70 bg-white/72 shadow-[0_24px_60px_rgba(125,104,75,0.12)] backdrop-blur-xl">
      <div className="border-b border-border/70 bg-card/80 px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="rounded-xl border border-primary/30 bg-primary/10 p-2">
            <ShieldAlert className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-foreground">
              {isRecoveredOnly ? "Recovered Candidate Findings" : "Final Vulnerability Report"}
            </h2>
            <p className="text-sm text-muted-foreground">
              {isRecoveredOnly
                ? "These candidates were recovered from the runtime transcript after finalization failed. They are not finalized findings yet."
                : "Verified and persisted findings from the completed runtime audit are summarized here for triage and export."}
            </p>
          </div>
        </div>
      </div>

      <div className="space-y-4 p-5">
        {orderedFindings.map((finding, index) => {
          const reportStatus = normalizeStatus(finding);
          const itemKey =
            finding.__kind === "finding" ? finding.id : `recovered-${index}-${finding.title}`;

          return (
            <article key={itemKey} className="rounded-2xl border border-border/60 bg-card/80 p-4 shadow-sm">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-base font-semibold text-foreground">{finding.title}</h3>
                    <Badge className={statusBadgeClass(reportStatus)}>{reportStatus}</Badge>
                    <Badge variant="outline" className="font-mono uppercase">{finding.severity}</Badge>
                    <Badge variant="outline" className="font-mono">{finding.vulnerability_type}</Badge>
                  </div>
                  {(finding.file_path || finding.line_start) && (
                    <div className="flex items-center gap-2 break-all text-sm text-muted-foreground">
                      <FileCode className="h-4 w-4" />
                      <span>
                        {finding.file_path}
                        {finding.line_start ? `:${finding.line_start}` : ""}
                        {finding.line_end && finding.line_end !== finding.line_start ? `-${finding.line_end}` : ""}
                      </span>
                    </div>
                  )}
                </div>

                <div className="text-right text-xs text-muted-foreground">
                  {hasConfidence(finding) ? (
                    <div>
                      Confidence: {(finding.ai_confidence ?? finding.confidence ?? 0).toFixed?.(2) ?? finding.confidence}
                    </div>
                  ) : null}
                  {finding.origin ? <div>Origin: {finding.origin}</div> : null}
                </div>
              </div>

              {finding.description ? (
                <p className="mt-3 text-sm leading-6 text-foreground/90">{finding.description}</p>
              ) : null}

              {(finding.source || finding.sink) && (
                <div className="mt-3 grid gap-2 md:grid-cols-2">
                  {finding.source ? (
                    <div className="rounded-xl border border-border/50 bg-muted/35 p-3 text-sm">
                      <div className="font-medium text-foreground">Source</div>
                      <div className="mt-1 break-all text-muted-foreground">{finding.source}</div>
                    </div>
                  ) : null}
                  {finding.sink ? (
                    <div className="rounded-xl border border-border/50 bg-muted/35 p-3 text-sm">
                      <div className="font-medium text-foreground">Sink</div>
                      <div className="mt-1 break-all text-muted-foreground">{finding.sink}</div>
                    </div>
                  ) : null}
                </div>
              )}

              {finding.impact ? (
                <div className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 text-sm">
                  <div className="font-medium text-foreground">Impact</div>
                  <div className="mt-1 text-muted-foreground">{finding.impact}</div>
                </div>
              ) : null}

              {finding.cve_justification ? (
                <div className="mt-3 rounded-xl border border-primary/20 bg-primary/5 p-3 text-sm">
                  <div className="font-medium text-foreground">CVE Justification</div>
                  <div className="mt-1 text-muted-foreground">{finding.cve_justification}</div>
                </div>
              ) : null}

              {finding.exploit_chain && finding.exploit_chain.length > 0 ? (
                <div className="mt-3 rounded-xl border border-border/50 bg-muted/30 p-3">
                  <div className="flex items-center gap-2 text-sm font-medium text-foreground">
                    <Link2 className="h-4 w-4" />
                    Exploit Chain
                  </div>
                  <div className="mt-2 space-y-2">
                    {finding.exploit_chain.map((step, stepIndex) => (
                      <div
                        key={`${itemKey}-chain-${stepIndex}`}
                        className="rounded-lg border border-border/40 bg-white/60 p-2.5 text-sm"
                      >
                        <div className="font-medium text-foreground">Step {step.step ?? stepIndex + 1}</div>
                        {step.location ? <div className="mt-1 break-all text-muted-foreground">{step.location}</div> : null}
                        {step.description ? <div className="mt-1 text-muted-foreground">{step.description}</div> : null}
                        {step.data_state ? <div className="mt-1 text-muted-foreground">Data: {step.data_state}</div> : null}
                        {step.bypass_reason ? <div className="mt-1 text-muted-foreground">Bypass: {step.bypass_reason}</div> : null}
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              {"poc" in finding && hasMeaningfulPoc(finding.poc) ? (
                <div className="mt-3 rounded-xl border border-rose-500/20 bg-rose-500/5 p-3">
                  <div className="flex items-center gap-2 text-sm font-medium text-foreground">
                    <AlertTriangle className="h-4 w-4 text-rose-500" />
                    PoC
                  </div>
                  {finding.poc.description ? <div className="mt-2 text-sm text-muted-foreground">{finding.poc.description}</div> : null}
                  {finding.poc.payload ? (
                    <pre className="mt-2 overflow-x-auto rounded-lg bg-black/85 p-3 text-xs text-green-300">{finding.poc.payload}</pre>
                  ) : null}
                  {finding.poc.steps && finding.poc.steps.length > 0 ? (
                    <div className="mt-2 space-y-2">
                      {finding.poc.steps.map((step, stepIndex) => (
                        <div key={`${itemKey}-poc-${stepIndex}`} className="rounded-lg border border-border/40 bg-white/60 p-2.5 text-sm">
                          <div className="font-medium text-foreground">Step {step.step ?? stepIndex + 1}</div>
                          {step.action ? <div className="mt-1 text-muted-foreground">Action: {step.action}</div> : null}
                          {step.request ? <div className="mt-1 break-all text-muted-foreground">Request: {step.request}</div> : null}
                          {step.expected_response ? <div className="mt-1 text-muted-foreground">Expected: {step.expected_response}</div> : null}
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : null}

              {(finding.verification_notes || finding.evidence_gaps?.length) ? (
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  {finding.verification_notes ? (
                    <div className="rounded-xl border border-border/50 bg-muted/30 p-3 text-sm">
                      <div className="flex items-center gap-2 font-medium text-foreground">
                        <CheckCircle2 className="h-4 w-4" />
                        Verification Notes
                      </div>
                      <div className="mt-1 text-muted-foreground">{finding.verification_notes}</div>
                    </div>
                  ) : null}
                  {finding.evidence_gaps && finding.evidence_gaps.length > 0 ? (
                    <div className="rounded-xl border border-border/50 bg-muted/30 p-3 text-sm">
                      <div className="font-medium text-foreground">Evidence Gaps</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {finding.evidence_gaps.map((gap) => (
                          <Badge key={`${itemKey}-${gap}`} variant="outline" className="font-mono text-[11px]">
                            {gap}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              ) : null}
            </article>
          );
        })}
      </div>
    </section>
  );
});

export default FinalReportPanel;
