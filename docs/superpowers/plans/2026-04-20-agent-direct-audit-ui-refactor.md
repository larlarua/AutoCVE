# Agent直审 UI Refactor Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the `Agent直审` page into a two-mode workspace with a Codex-style session manager and an IDE-style project directory view while preserving the existing direct-audit data flows.

**Architecture:** Keep `/agent-direct-audit` as a single route, move shared project/session/file loading to a page shell, and split the UI into focused session and workspace mode components. Extract tab-state helpers into pure functions so the new IDE-tab behavior can be verified independently before wiring it into the page.

**Tech Stack:** React 18, TypeScript, Vite, Tailwind CSS, Radix UI, lucide-react, Node 25 built-in test runner for pure TS helpers, existing direct-audit hooks/APIs.

---

## File map

- Modify: `frontend/src/pages/AgentDirectAudit/index.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/PageHeader.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/ModeSwitcher.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/SessionWorkspace.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/ProjectWorkspace.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/FileTree.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/EditorTabs.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/CodePreview.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/ReportSummaryCard.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/lib/workspaceState.ts`
- Test: `frontend/src/pages/AgentDirectAudit/lib/workspaceState.test.ts`

## Chunk 1: Extract workspace state helpers

### Task 1: Add tab-state helper tests first

**Files:**
- Test: `frontend/src/pages/AgentDirectAudit/lib/workspaceState.test.ts`
- Create: `frontend/src/pages/AgentDirectAudit/lib/workspaceState.ts`

- [ ] **Step 1: Write the failing test**

Create tests for:
- opening a new file appends a tab and activates it
- opening an already-open file only changes the active tab
- closing an inactive tab preserves the active tab
- closing the active tab switches to the nearest remaining tab
- closing the last tab clears the active path

- [ ] **Step 2: Run test to verify it fails**

Run: `node --experimental-strip-types --test frontend/src/pages/AgentDirectAudit/lib/workspaceState.test.ts`
Expected: FAIL because `workspaceState.ts` does not exist yet.

- [ ] **Step 3: Write minimal implementation**

Implement pure helpers such as:
- `openFileTab`
- `closeFileTab`
- `syncActiveFileTab`

- [ ] **Step 4: Run test to verify it passes**

Run: `node --experimental-strip-types --test frontend/src/pages/AgentDirectAudit/lib/workspaceState.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/AgentDirectAudit/lib/workspaceState.ts frontend/src/pages/AgentDirectAudit/lib/workspaceState.test.ts
git commit -m "test: cover agent direct audit workspace tab state"
```

## Chunk 2: Split the page shell and top-level modes

### Task 2: Build the page shell and mode switch

**Files:**
- Modify: `frontend/src/pages/AgentDirectAudit/index.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/PageHeader.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/ModeSwitcher.tsx`

- [ ] **Step 1: Add a failing behavior check**

Use the new helpers as a safety net and define the target shell behavior in code comments and component props before moving layout logic.

- [ ] **Step 2: Move shared page concerns into a shell**

Keep these responsibilities in `index.tsx`:
- URL param sync
- project loading
- session loading
- file list loading
- file content loading
- session stream hooks

Introduce a `mode` state with a default of `session`, optionally syncing to `?mode=`.

- [ ] **Step 3: Add focused shell components**

`PageHeader.tsx` should render:
- title
- concise helper copy
- project selector
- mode switch

`ModeSwitcher.tsx` should render the two green/white segmented buttons:
- `会话管理`
- `项目目录`

- [ ] **Step 4: Run type-check**

Run: `npm --prefix frontend run type-check`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/AgentDirectAudit/index.tsx frontend/src/pages/AgentDirectAudit/components/PageHeader.tsx frontend/src/pages/AgentDirectAudit/components/ModeSwitcher.tsx
git commit -m "refactor: add agent direct audit page shell"
```

## Chunk 3: Rebuild the session management mode

### Task 3: Implement the Codex-style session workspace

**Files:**
- Create: `frontend/src/pages/AgentDirectAudit/components/SessionWorkspace.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/ReportSummaryCard.tsx`
- Modify: `frontend/src/pages/AgentDirectAudit/index.tsx`

- [ ] **Step 1: Move session-only UI into `SessionWorkspace.tsx`**

Render:
- collapsible left sidebar
- project summary
- session list
- new session button
- report summary card at the bottom
- large chat panel on the right

- [ ] **Step 2: Remove old right-rail session chrome**

Do not render:
- `Inspector`
- `Findings`
- `Tools`
- `Signals`

Do not leave placeholder cards behind.

- [ ] **Step 3: Preserve current chat behaviors**

Keep:
- initial session creation flow
- follow-up composer
- streaming timeline
- report sync actions
- existing session reload behavior

- [ ] **Step 4: Run type-check**

Run: `npm --prefix frontend run type-check`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/AgentDirectAudit/index.tsx frontend/src/pages/AgentDirectAudit/components/SessionWorkspace.tsx frontend/src/pages/AgentDirectAudit/components/ReportSummaryCard.tsx
git commit -m "refactor: rebuild agent direct audit session workspace"
```

## Chunk 4: Rebuild the project directory mode

### Task 4: Implement the IDE-style workspace

**Files:**
- Create: `frontend/src/pages/AgentDirectAudit/components/ProjectWorkspace.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/FileTree.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/EditorTabs.tsx`
- Create: `frontend/src/pages/AgentDirectAudit/components/CodePreview.tsx`
- Modify: `frontend/src/pages/AgentDirectAudit/index.tsx`

- [ ] **Step 1: Move file tree rendering into `FileTree.tsx`**

Preserve recursive tree rendering and selected-file highlighting, but style it as an IDE sidebar.

- [ ] **Step 2: Wire tab state through the tested helpers**

Use `openFileTab`, `closeFileTab`, and `syncActiveFileTab` to manage:
- `openTabs`
- `activeTabPath`

- [ ] **Step 3: Build the right-side editor frame**

Render:
- top tab strip
- active file badge or metadata
- code preview area
- empty state when no file is open
- loading/error states while fetching content

- [ ] **Step 4: Run type-check**

Run: `npm --prefix frontend run type-check`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/AgentDirectAudit/index.tsx frontend/src/pages/AgentDirectAudit/components/ProjectWorkspace.tsx frontend/src/pages/AgentDirectAudit/components/FileTree.tsx frontend/src/pages/AgentDirectAudit/components/EditorTabs.tsx frontend/src/pages/AgentDirectAudit/components/CodePreview.tsx
git commit -m "feat: add ide-style agent direct audit workspace"
```

## Chunk 5: Polish and verify

### Task 5: Finish styling and run end-to-end verification

**Files:**
- Modify: `frontend/src/pages/AgentDirectAudit/index.tsx`
- Modify: `frontend/src/pages/AgentDirectAudit/components/*.tsx`

- [ ] **Step 1: Apply final visual polish**

Ensure:
- green/white visual consistency
- generous right-side workspace sizing
- clean empty states
- smooth sidebar collapse affordances
- mobile-safe overflow behavior

- [ ] **Step 2: Run helper tests**

Run: `node --experimental-strip-types --test frontend/src/pages/AgentDirectAudit/lib/workspaceState.test.ts`
Expected: PASS.

- [ ] **Step 3: Run frontend verification**

Run: `npm --prefix frontend run type-check`
Expected: PASS.

Run: `npm --prefix frontend run build`
Expected: PASS.

- [ ] **Step 4: Manual verification checklist**

Verify in the browser:
- switching between `会话管理` and `项目目录` keeps the selected project
- session sidebar can collapse and expand
- report summary stays in the left column
- no inspector/findings/tools/signals panels remain visible
- clicking files opens editor tabs
- clicking an already-open file focuses its existing tab
- closing tabs follows the expected fallback behavior

- [ ] **Step 5: Commit**

```bash
git add frontend/src/pages/AgentDirectAudit
git commit -m "feat: redesign agent direct audit ui"
```
