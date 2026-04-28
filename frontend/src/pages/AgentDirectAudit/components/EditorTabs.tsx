import { X } from "lucide-react";

import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/shared/utils/utils";

function fileName(path: string) {
  return path.split("/").pop() || path;
}

export function EditorTabs({
  openTabs,
  activeTabPath,
  onSelect,
  onClose,
}: {
  openTabs: string[];
  activeTabPath: string;
  onSelect: (path: string) => void;
  onClose: (path: string) => void;
}) {
  if (openTabs.length === 0) {
    return (
      <div className="flex h-14 items-center rounded-t-[28px] border-b border-[rgba(177,200,185,.28)] bg-[rgba(246,249,247,.92)] px-5 text-sm text-slate-500">
        选择文件后会在这里打开标签页
      </div>
    );
  }

  return (
    <ScrollArea className="w-full whitespace-nowrap rounded-t-[28px] border-b border-[rgba(177,200,185,.28)] bg-[rgba(246,249,247,.92)]">
      <div className="flex min-w-full items-center gap-2 px-4 py-3">
        {openTabs.map((path) => {
          const active = path === activeTabPath;
          return (
            <button
              key={path}
              type="button"
              onClick={() => onSelect(path)}
              className={cn(
                "group inline-flex max-w-[240px] items-center gap-2 rounded-[16px] border px-3 py-2 text-left text-sm transition",
                active
                  ? "border-[rgba(170,194,178,.4)] bg-white text-slate-900 shadow-[0_12px_24px_rgba(94,122,99,.10)]"
                  : "border-transparent bg-[rgba(236,242,238,.9)] text-slate-500 hover:border-[rgba(177,200,185,.28)] hover:bg-white hover:text-slate-900",
              )}
            >
              <span className="truncate">{fileName(path)}</span>
              <span
                role="button"
                tabIndex={-1}
                onClick={(event) => {
                  event.stopPropagation();
                  onClose(path);
                }}
                className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-slate-400 transition hover:bg-[rgba(15,23,42,.06)] hover:text-slate-700"
              >
                <X className="h-3.5 w-3.5" />
              </span>
            </button>
          );
        })}
      </div>
    </ScrollArea>
  );
}
