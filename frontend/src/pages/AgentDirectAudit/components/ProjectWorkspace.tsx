import { FolderTree } from "lucide-react";

import { ScrollArea } from "@/components/ui/scroll-area";
import { CodePreview } from "@/pages/AgentDirectAudit/components/CodePreview";
import { EditorTabs } from "@/pages/AgentDirectAudit/components/EditorTabs";
import { FileTree, type FileEntry } from "@/pages/AgentDirectAudit/components/FileTree";
import type { Project, ProjectFileContent } from "@/shared/types";

const panelClass =
  "overflow-hidden rounded-[30px] border border-[rgba(177,200,185,.38)] bg-[linear-gradient(180deg,rgba(255,255,255,.97),rgba(243,248,244,.94))] shadow-[0_24px_60px_rgba(96,120,101,.08)]";

export function ProjectWorkspace({
  selectedProject,
  files,
  activeTabPath,
  openTabs,
  onOpenFile,
  onSelectTab,
  onCloseTab,
  filePreview,
  filePreviewLoading,
  filePreviewError,
}: {
  selectedProject: Project | null;
  files: FileEntry[];
  activeTabPath: string;
  openTabs: string[];
  onOpenFile: (path: string) => void;
  onSelectTab: (path: string) => void;
  onCloseTab: (path: string) => void;
  filePreview: ProjectFileContent | null;
  filePreviewLoading: boolean;
  filePreviewError: string | null;
}) {
  return (
    <section className="grid gap-5 xl:grid-cols-[320px_minmax(0,1fr)]">
      <aside className={`${panelClass} min-h-[720px]`}>
        <div className="border-b border-[rgba(177,200,185,.28)] bg-[radial-gradient(circle_at_top_left,rgba(225,239,228,.92),rgba(255,255,255,.7)_62%)] px-5 py-5">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-[18px] border border-[rgba(177,200,185,.32)] bg-white/80 text-[rgb(94,122,99)]">
              <FolderTree className="h-4.5 w-4.5" />
            </span>
            <div className="min-w-0">
              <div className="text-base font-semibold text-slate-900">项目目录</div>
              <div className="truncate text-xs text-slate-500">{selectedProject?.name || "未选择项目"}</div>
            </div>
          </div>
        </div>
        <ScrollArea className="h-[560px] px-3 py-4">
          <FileTree files={files} selectedPath={activeTabPath} onSelect={onOpenFile} />
        </ScrollArea>
      </aside>

      <div className={`${panelClass} min-h-[720px]`}>
        <EditorTabs openTabs={openTabs} activeTabPath={activeTabPath} onSelect={onSelectTab} onClose={onCloseTab} />
        <CodePreview
          activeTabPath={activeTabPath}
          filePreview={filePreview}
          filePreviewLoading={filePreviewLoading}
          filePreviewError={filePreviewError}
        />
      </div>
    </section>
  );
}
