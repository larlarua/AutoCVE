import { FileCode2, Loader2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { ProjectFileContent } from "@/shared/types";

function buildPreviewLines(filePreview: ProjectFileContent | null): Array<{ number: number; content: string }> {
  if (!filePreview) {
    return [];
  }

  return filePreview.content.split(/\r?\n/).map((line, index) => ({
    number: index + 1,
    content: line,
  }));
}

export function CodePreview({
  activeTabPath,
  filePreview,
  filePreviewLoading,
  filePreviewError,
}: {
  activeTabPath: string;
  filePreview: ProjectFileContent | null;
  filePreviewLoading: boolean;
  filePreviewError: string | null;
}) {
  const previewLines = buildPreviewLines(filePreview);

  if (!activeTabPath) {
    return (
      <div className="flex min-h-[520px] items-center justify-center px-8 py-12">
        <div className="max-w-md text-center">
          <span className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-[20px] border border-[rgba(177,200,185,.32)] bg-[rgba(240,247,242,.92)] text-[rgb(94,122,99)]">
            <FileCode2 className="h-6 w-6" />
          </span>
          <h3 className="text-xl font-semibold text-slate-900">未打开文件</h3>
        </div>
      </div>
    );
  }

  if (filePreviewLoading) {
    return (
      <div className="flex min-h-[520px] items-center justify-center gap-3 text-sm text-slate-500">
        <Loader2 className="h-4 w-4 animate-spin" />
        加载文件...
      </div>
    );
  }

  if (filePreviewError) {
    return (
      <div className="flex min-h-[520px] items-center justify-center px-8 py-12 text-center text-sm text-rose-600">
        {filePreviewError}
      </div>
    );
  }

  if (!filePreview) {
    return null;
  }

  return (
    <div className="flex min-h-[520px] flex-col">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[rgba(177,200,185,.28)] bg-white/80 px-5 py-4">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-slate-900">{filePreview.path}</div>
          <div className="mt-1 text-xs text-slate-500">{previewLines.length} lines</div>
        </div>
        <div className="flex items-center gap-2">
          {filePreview.truncated ? <Badge variant="outline">已截断</Badge> : null}
          <Badge variant="secondary">{Math.max(filePreview.size, 0)} bytes</Badge>
        </div>
      </div>

      <ScrollArea className="min-h-[460px] flex-1">
        <div className="bg-[linear-gradient(180deg,rgb(16,24,20),rgb(11,18,15))] px-0 py-4 font-mono text-[12px] leading-6 text-slate-100">
          {previewLines.map((line) => (
            <div
              key={`${filePreview.path}:${line.number}`}
              className="grid grid-cols-[64px_minmax(0,1fr)] gap-0 px-4 transition hover:bg-white/5"
            >
              <span className="select-none pr-4 text-right text-slate-500">{line.number}</span>
              <pre className="overflow-x-auto whitespace-pre-wrap break-words">{line.content || " "}</pre>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}
