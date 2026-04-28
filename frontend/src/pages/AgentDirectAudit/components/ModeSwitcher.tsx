import { FileCode2, MessageSquareText } from "lucide-react";

import { cn } from "@/shared/utils/utils";

export type AgentDirectAuditMode = "session" | "workspace";

const MODE_OPTIONS: Array<{
  value: AgentDirectAuditMode;
  label: string;
  icon: typeof MessageSquareText;
}> = [
  {
    value: "session",
    label: "会话管理",
    icon: MessageSquareText,
  },
  {
    value: "workspace",
    label: "项目目录",
    icon: FileCode2,
  },
];

export function ModeSwitcher({
  mode,
  onChange,
}: {
  mode: AgentDirectAuditMode;
  onChange: (mode: AgentDirectAuditMode) => void;
}) {
  return (
    <div className="inline-flex rounded-[22px] border border-[rgba(170,194,178,.38)] bg-white/85 p-1.5 shadow-[0_18px_38px_rgba(96,120,101,.08)]">
      {MODE_OPTIONS.map((option) => {
        const Icon = option.icon;
        const active = option.value === mode;
        return (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            className={cn(
              "group flex min-w-[160px] items-center gap-3 rounded-[18px] px-4 py-3 text-left transition-all duration-200",
              active
                ? "bg-[linear-gradient(135deg,rgba(124,163,133,.98),rgba(94,122,99,.98))] text-white shadow-[0_16px_32px_rgba(94,122,99,.24)]"
                : "text-slate-600 hover:bg-[rgba(240,247,242,.92)] hover:text-slate-900",
            )}
          >
            <span
              className={cn(
                "flex h-10 w-10 items-center justify-center rounded-2xl border transition-all",
                active
                  ? "border-white/20 bg-white/14 text-white"
                  : "border-[rgba(170,194,178,.32)] bg-[rgba(240,247,242,.86)] text-[rgb(94,122,99)]",
              )}
            >
              <Icon className="h-4.5 w-4.5" />
            </span>
            <span className="truncate text-sm font-semibold">{option.label}</span>
          </button>
        );
      })}
    </div>
  );
}
