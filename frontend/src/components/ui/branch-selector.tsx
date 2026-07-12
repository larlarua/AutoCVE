/**
 * Branch Selector with Search
 * 支持搜索功能的分支选择器，解决分支过多时无法选择的问题
 */

import * as React from "react";
import { Check, ChevronsUpDown, GitBranch, Search } from "lucide-react";
import { cn } from "@/shared/utils/utils";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

interface BranchSelectorProps {
  value: string;
  onChange: (value: string) => void;
  branches: string[];
  placeholder?: string;
  disabled?: boolean;
  className?: string;
}

export function BranchSelector({
  value,
  onChange,
  branches,
  placeholder = "选择分支",
  disabled = false,
  className,
}: BranchSelectorProps) {
  const [open, setOpen] = React.useState(false);
  const [searchQuery, setSearchQuery] = React.useState("");
  const listRef = React.useRef<HTMLDivElement>(null);

  // 过滤分支列表
  const filteredBranches = React.useMemo(() => {
    if (!searchQuery) return branches;
    const query = searchQuery.toLowerCase();
    return branches.filter((branch) =>
      branch.toLowerCase().includes(query)
    );
  }, [branches, searchQuery]);

  // 处理滚轮事件
  const handleWheel = React.useCallback((e: React.WheelEvent<HTMLDivElement>) => {
    const container = listRef.current;
    if (container) {
      container.scrollTop += e.deltaY;
      e.stopPropagation();
    }
  }, []);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          disabled={disabled}
          className={cn(
            "h-9 justify-between cyber-input font-mono text-sm",
            !value && "text-muted-foreground",
            className
          )}
        >
          <span className="truncate">
            {value || placeholder}
          </span>
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="min-w-[280px] w-auto max-w-[400px] p-0 cyber-dialog border-border"
        align="start"
        onWheel={handleWheel}
      >
        {/* 搜索框 */}
        <div className="flex items-center border-b px-3">
          <Search className="mr-2 h-4 w-4 shrink-0 opacity-50" />
          <input
            placeholder="搜索分支..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="flex h-10 w-full rounded-md bg-transparent py-3 text-sm outline-none ring-0 border-none focus:outline-none focus:ring-0 placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50 font-mono"
          />
        </div>

        {/* 分支列表 */}
        <div
          ref={listRef}
          className="max-h-[300px] overflow-y-auto overscroll-contain"
        >
          {filteredBranches.length === 0 ? (
            <div className="py-6 text-center text-sm font-mono text-muted-foreground">
              未找到匹配的分支
            </div>
          ) : (
            <div className="p-1">
              {filteredBranches.map((branch) => (
                <div
                  key={branch}
                  onClick={() => {
                    onChange(branch);
                    setOpen(false);
                    setSearchQuery("");
                  }}
                  className={cn(
                    "flex items-center gap-2 px-2 py-1.5 text-sm font-mono rounded-sm cursor-pointer",
                    "hover:bg-accent hover:text-accent-foreground",
                    value === branch && "bg-accent"
                  )}
                >
                  <Check
                    className={cn(
                      "h-4 w-4 shrink-0",
                      value === branch ? "opacity-100" : "opacity-0"
                    )}
                  />
                  <GitBranch className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <span className="truncate">{branch}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* 底部统计 */}
        {branches.length > 0 && (
          <div className="border-t px-3 py-2 text-xs text-muted-foreground font-mono">
            共 {branches.length} 个分支
            {searchQuery && filteredBranches.length !== branches.length && (
              <span>，匹配 {filteredBranches.length} 个</span>
            )}
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}

export default BranchSelector;
