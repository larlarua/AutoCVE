import { useMemo, useState } from "react";
import { FileCode2, Folder, FolderOpen } from "lucide-react";

import { cn } from "@/shared/utils/utils";

export type FileEntry = { path: string; size: number };

type TreeNode = {
  name: string;
  path: string;
  type: "directory" | "file";
  children: TreeNode[];
};

function buildFileTree(files: FileEntry[]): TreeNode[] {
  const root: TreeNode[] = [];

  function upsertChild(children: TreeNode[], node: TreeNode) {
    const existing = children.find((child) => child.name === node.name && child.type === node.type);
    if (existing) {
      return existing;
    }
    children.push(node);
    return node;
  }

  for (const file of files) {
    const segments = file.path.split("/").filter(Boolean);
    let currentChildren = root;
    let currentPath = "";

    segments.forEach((segment, index) => {
      currentPath = currentPath ? `${currentPath}/${segment}` : segment;
      const isLeaf = index === segments.length - 1;
      const node = upsertChild(currentChildren, {
        name: segment,
        path: currentPath,
        type: isLeaf ? "file" : "directory",
        children: [],
      });
      currentChildren = node.children;
    });
  }

  const sortNodes = (nodes: TreeNode[]): TreeNode[] =>
    [...nodes]
      .map((node) => ({
        ...node,
        children: sortNodes(node.children),
      }))
      .sort((left, right) => {
        if (left.type !== right.type) {
          return left.type === "directory" ? -1 : 1;
        }
        return left.name.localeCompare(right.name);
      });

  return sortNodes(root);
}

function TreeNodeItem({
  node,
  depth,
  selectedPath,
  onSelect,
}: {
  node: TreeNode;
  depth: number;
  selectedPath: string;
  onSelect: (path: string) => void;
}) {
  const [open, setOpen] = useState(depth < 2);

  if (node.type === "file") {
    const active = selectedPath === node.path;
    return (
      <button
        type="button"
        onClick={() => onSelect(node.path)}
        className={cn(
          "flex w-full items-center gap-2 rounded-[14px] px-3 py-2 text-left text-sm transition",
          active
            ? "bg-[rgba(222,236,226,.96)] text-slate-900 shadow-[0_8px_18px_rgba(94,122,99,.10)]"
            : "text-slate-600 hover:bg-[rgba(241,247,243,.9)] hover:text-slate-900",
        )}
        style={{ paddingLeft: `${depth * 14 + 14}px` }}
      >
        <FileCode2 className={cn("h-4 w-4 shrink-0", active ? "text-[rgb(94,122,99)]" : "text-slate-400")} />
        <span className="truncate">{node.name}</span>
      </button>
    );
  }

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center gap-2 rounded-[14px] px-3 py-2 text-left text-sm font-medium text-slate-700 transition hover:bg-[rgba(241,247,243,.9)]"
        style={{ paddingLeft: `${depth * 14 + 14}px` }}
      >
        {open ? <FolderOpen className="h-4 w-4 text-[rgb(94,122,99)]" /> : <Folder className="h-4 w-4 text-slate-400" />}
        <span className="truncate">{node.name}</span>
      </button>
      {open
        ? node.children.map((child) => (
            <TreeNodeItem key={child.path} node={child} depth={depth + 1} selectedPath={selectedPath} onSelect={onSelect} />
          ))
        : null}
    </div>
  );
}

export function FileTree({
  files,
  selectedPath,
  onSelect,
}: {
  files: FileEntry[];
  selectedPath: string;
  onSelect: (path: string) => void;
}) {
  const tree = useMemo(() => buildFileTree(files), [files]);

  if (tree.length === 0) {
    return (
      <div className="rounded-[20px] border border-dashed border-[rgba(177,200,185,.28)] bg-white/78 px-4 py-6 text-sm text-slate-500">
        暂无文件
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {tree.map((node) => (
        <TreeNodeItem key={node.path} node={node} depth={0} selectedPath={selectedPath} onSelect={onSelect} />
      ))}
    </div>
  );
}
