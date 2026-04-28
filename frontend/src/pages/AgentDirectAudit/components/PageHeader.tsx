import { FolderGit2, Loader2, Sparkles } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ModeSwitcher, type AgentDirectAuditMode } from "@/pages/AgentDirectAudit/components/ModeSwitcher";
import type { Project } from "@/shared/types";

function sourceLabel(project: Project | null) {
  if (!project) {
    return "未选择项目";
  }

  if (project.source_type === "local_directory") {
    return "本地项目";
  }
  if (project.source_type === "repository") {
    return "仓库项目";
  }
  if (project.source_type === "zip") {
    return "ZIP 项目";
  }

  return project.source_type;
}

export function PageHeader({
  mode,
  onModeChange,
  projects,
  projectsLoading,
  selectedProjectId,
  selectedProject,
  onProjectChange,
}: {
  mode: AgentDirectAuditMode;
  onModeChange: (mode: AgentDirectAuditMode) => void;
  projects: Project[];
  projectsLoading: boolean;
  selectedProjectId: string;
  selectedProject: Project | null;
  onProjectChange: (projectId: string) => void;
}) {
  return (
    <section className="relative overflow-hidden rounded-[34px] border border-white/70 bg-[linear-gradient(180deg,rgba(255,255,255,.95),rgba(245,249,246,.92))] p-6 shadow-[0_28px_80px_rgba(89,108,94,.10)]">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(202,222,208,.42),transparent_28%),radial-gradient(circle_at_bottom_left,rgba(224,236,228,.7),transparent_32%)]" />
      <div className="relative flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <Badge className="rounded-full border-0 bg-[rgba(222,236,226,.95)] px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-[rgb(94,122,99)] shadow-none">
              Agent Direct Audit
            </Badge>
            <Badge variant="outline" className="rounded-full border-[rgba(170,194,178,.45)] bg-white/80 text-slate-600">
              {sourceLabel(selectedProject)}
            </Badge>
          </div>
          <div className="flex items-center gap-3">
            <span className="flex h-11 w-11 items-center justify-center rounded-[20px] border border-[rgba(170,194,178,.38)] bg-white/85 text-[rgb(94,122,99)] shadow-[0_10px_24px_rgba(94,122,99,.12)]">
              <Sparkles className="h-5 w-5" />
            </span>
            <h1 className="text-4xl font-semibold tracking-[-0.04em] text-slate-950">Agent直审</h1>
          </div>
        </div>

        <div className="flex flex-col gap-3 xl:items-end">
          <ModeSwitcher mode={mode} onChange={onModeChange} />
          <div className="flex items-center gap-3 rounded-[20px] border border-[rgba(170,194,178,.34)] bg-white/88 px-4 py-3 shadow-[0_12px_30px_rgba(96,120,101,.07)]">
            <span className="flex h-10 w-10 items-center justify-center rounded-2xl border border-[rgba(170,194,178,.32)] bg-[rgba(240,247,242,.92)] text-[rgb(94,122,99)]">
              <FolderGit2 className="h-4.5 w-4.5" />
            </span>
            <div className="min-w-[240px] flex-1">
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">当前项目</div>
              <Select value={selectedProjectId} onValueChange={onProjectChange} disabled={projectsLoading || projects.length === 0}>
                <SelectTrigger className="h-auto w-full border-0 bg-transparent px-0 py-0 text-left shadow-none focus:ring-0">
                  <SelectValue placeholder={projectsLoading ? "加载项目..." : projects.length === 0 ? "暂无项目" : "请选择项目"} />
                </SelectTrigger>
                <SelectContent>
                  {projects.map((project) => (
                    <SelectItem key={project.id} value={project.id}>
                      {project.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {projectsLoading ? <Loader2 className="h-4 w-4 animate-spin text-slate-400" /> : null}
          </div>
        </div>
      </div>
    </section>
  );
}
