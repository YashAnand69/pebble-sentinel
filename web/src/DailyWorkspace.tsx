import { useEffect, useRef, useState } from "react";
import { ArrowUpRight, Download, FileText, FolderOpen, ShieldCheck, Trash2 } from "lucide-react";
import {
  approvalMatches,
  documentAction,
  formatLocalJson,
  MAX_HISTORY,
  parseDailyCheck,
  validateDraftName,
  validateLocalFile,
  workspacePayload,
  serializeDailyAudit,
  upsertDailyAudit,
} from "./daily-workspace";
import type { DailyAction, DailyCheck, DailyAudit } from "./daily-workspace";
import "./daily-workspace.css";
type Operation = {
  kind: "open" | "download";
  action: DailyAction;
  revision: number;
  file?: File;
  text?: string;
  name?: string;
};
function download(text: string, name: string, mime = "text/plain;charset=utf-8") {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export default function DailyWorkspace() {
  const [file, setFile] = useState<File | null>(null),
    [content, setContent] = useState<string | null>(null),
    [draft, setDraft] = useState(""),
    [filename, setFilename] = useState("my-notes.md"),
    [task, setTask] = useState("Meeting notes");
  const [history, setHistory] = useState<DailyAction[]>([]),
    [audit, setAudit] = useState<DailyAudit[]>([]),
    [check, setCheck] = useState<DailyCheck | null>(null),
    [held, setHeld] = useState<Operation | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(
      "Choose a document or write a draft. Selection alone does not open a file.",
    );
  const revision = useRef(0),
    lock = useRef(false),
    controller = useRef<AbortController | null>(null),
    mounted = useRef(true),
    fileInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      controller.current?.abort();
    };
  }, []);
  function invalidate() {
    revision.current++;
    controller.current?.abort();
    setHeld(null);
    setCheck(null);
    setError("");
  }
  function clear() {
    invalidate();
    setFile(null);
    setContent(null);
    setDraft("");
    setFilename("my-notes.md");
    setHistory([]);
    setAudit([]);
    setNotice(
      "Workspace cleared. Documents, drafts, decisions, and history were removed from this tab.",
    );
    if (fileInput.current) fileInput.current.value = "";
  }
  async function complete(op: Operation, result: DailyCheck, approved: boolean) {
    if (op.revision !== revision.current || result.decision === "block") return;
    try {
      if (op.kind === "open") {
        const text = await op.file!.text();
        if (!mounted.current || op.revision !== revision.current) return;
        setContent(text);
        setNotice("Document opened locally. Its content has not been sent to the guard.");
      } else {
        download(op.text!, op.name!);
        setNotice("Draft download requested. Your original document was not changed.");
      }
      setHistory((h) => [...h, op.action]);
      setAudit((a) =>
        upsertDailyAudit(a, {
          id: result.record.id,
          action: op.action,
          decision: result.decision,
          completed: true,
          approved,
          surprise_bits: result.record.surprise_bits,
          rules: result.record.rules,
        }),
      );
      setHeld(null);
    } catch {
      if (mounted.current)
        setError("The local operation failed. No completed action was added to history.");
    }
  }
  async function run(kind: Operation["kind"]) {
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setError("");
    setHeld(null);
    setCheck(null);
    const runRevision = revision.current;
    const ctl = new AbortController();
    controller.current = ctl;
    const timeout = setTimeout(() => ctl.abort(), 20000);
    try {
      let op: Operation;
      if (kind === "open") {
        if (!file) throw new Error("Choose a local document first.");
        validateLocalFile(file.name, file.size);
        op = { kind, file, action: documentAction("read", file.name), revision: revision.current };
      } else {
        validateDraftName(filename);
        if (!draft.trim()) throw new Error("Write a draft before downloading.");
        if (new Blob([draft]).size > 256 * 1024)
          throw new Error("Keep the draft at 256 KB or smaller.");
        op = {
          kind,
          text: draft,
          name: filename,
          action: documentAction("write", filename),
          revision: revision.current,
        };
      }
      const response = await fetch("/api/workspace/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(workspacePayload(history, op.action)),
        signal: ctl.signal,
      });
      if (!response.ok)
        throw new Error("The guard is unavailable. Nothing was opened or downloaded. Try again.");
      const result = parseDailyCheck(await response.json());
      if (ctl.signal.aborted || !mounted.current || op.revision !== revision.current) return;
      if (result.record.pebble !== `${op.action.verb} ${op.action.object} via file-tool .`)
        throw new Error(
          "The response did not match your action. Nothing was opened or downloaded.",
        );
      setCheck(result);
      setAudit((a) =>
        upsertDailyAudit(a, {
          id: result.record.id,
          action: op.action,
          decision: result.decision,
          completed: false,
          approved: false,
          surprise_bits: result.record.surprise_bits,
          rules: result.record.rules,
        }),
      );
      if (result.decision === "allow") await complete(op, result, false);
      else {
        if (result.decision === "hold") {
          setHeld(op);
          setNotice(
            "Paused before opening or downloading. Review this exact action, then approve once if you want to proceed.",
          );
        } else
          setNotice(
            "Blocked. This file was not opened and this draft was not downloaded. There is no override.",
          );
      }
    } catch (e) {
      if (mounted.current && runRevision === revision.current)
        setError(
          ctl.signal.aborted
            ? "The check was cancelled or timed out. Nothing was opened or downloaded."
            : e instanceof Error
              ? e.message
              : "The check failed. Nothing was opened or downloaded.",
        );
    } finally {
      clearTimeout(timeout);
      if (controller.current === ctl) controller.current = null;
      lock.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  async function approve() {
    if (lock.current || !held || !check || check.decision !== "hold") return;
    const action =
      held.kind === "open" && file
        ? documentAction("read", file.name)
        : documentAction("write", filename);
    if (!approvalMatches(held, revision.current, action)) {
      setHeld(null);
      setError("Inputs changed. Run a new guard check.");
      return;
    }
    lock.current = true;
    setBusy(true);
    try {
      await complete(held, check, true);
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  return (
    <section
      id="daily-workspace"
      className="daily-workspace section-wrap"
      aria-labelledby="daily-title"
    >
      <div className="daily-heading">
        <div>
          <span className="eyebrow">USE SENTINEL TODAY</span>
          <h2 id="daily-title">
            Your documents.
            <br />
            <em>A deliberate next step.</em>
          </h2>
          <p>
            Open a local document, write your own notes, and guard the download. This website checks
            its own buttons; it does not protect other apps or agents on your device.
          </p>
        </div>
        <div className="daily-privacy">
          <ShieldCheck size={22} />
          <strong>Content stays in this tab</strong>
          <span>
            Only action classes and up to 24 completed actions reach the guard. No filenames,
            document text, or draft text are sent.
          </span>
        </div>
      </div>
      <div className="daily-presets" aria-label="Workspace task">
        {["Meeting notes", "Project report", "Task list"].map((label) => (
          <button
            key={label}
            className={task === label ? "selected" : ""}
            onClick={() => setTask(label)}
          >
            {label}
          </button>
        ))}
        <span>
          Manual workspace · {history.length}/{MAX_HISTORY} completed actions
        </span>
      </div>
      <div className="daily-columns">
        <article className="daily-panel">
          <div className="daily-panel-title">
            <FolderOpen size={20} />
            <h3>1. Open a document</h3>
            <span>Read only</span>
          </div>
          <p>
            Choose a small text document. We classify its name locally; sensitive or configuration
            names may be refused. This is a limited pilot, not content scanning.
          </p>
          <label className="daily-file">
            Choose .txt, .md, .json, or .csv
            <input
              ref={fileInput}
              type="file"
              accept=".txt,.md,.json,.csv"
              disabled={busy}
              onChange={(e) => {
                invalidate();
                setContent(null);
                const next = e.target.files?.[0] ?? null;
                setFile(next);
                if (next)
                  try {
                    validateLocalFile(next.name, next.size);
                  } catch (err) {
                    setError((err as Error).message);
                    setFile(null);
                  }
              }}
            />
          </label>
          {file && (
            <div className="daily-file-meta">
              <FileText size={16} />
              <span>{file.name}</span>
              <small>{(file.size / 1024).toFixed(1)} KB · not uploaded</small>
            </div>
          )}
          <button
            className="daily-primary"
            disabled={busy || !file || history.length >= MAX_HISTORY}
            onClick={() => void run("open")}
          >
            <ShieldCheck size={17} />
            {busy ? "Checking…" : "Guard & open locally"}
          </button>
          {content !== null && (
            <div className="daily-document">
              <div>Local document preview</div>
              <div className="daily-local-tools">
                <button
                  disabled={busy}
                  onClick={() => {
                    invalidate();
                    setDraft(content);
                    setNotice(
                      "Opened text copied into your draft locally. Edit it, then guard the download.",
                    );
                  }}
                >
                  Use file as draft
                </button>
                {file?.name.toLowerCase().endsWith(".json") && (
                  <button
                    disabled={busy}
                    onClick={() => {
                      try {
                        const formatted = formatLocalJson(content);
                        invalidate();
                        setDraft(formatted);
                        setFilename("formatted-document.json");
                        setNotice(
                          "JSON formatted locally into your draft. Review it before downloading.",
                        );
                      } catch {
                        setError("This document is not valid JSON. Your draft was left unchanged.");
                      }
                    }}
                  >
                    Format JSON into draft
                  </button>
                )}
              </div>
              <pre tabIndex={0}>{content || "(Empty document)"}</pre>
            </div>
          )}
        </article>
        <article className="daily-panel">
          <div className="daily-panel-title">
            <FileText size={20} />
            <h3>2. Write your {task.toLowerCase()}</h3>
            <span>You author it</span>
          </div>
          <p>
            Work from your document or start fresh. There is no AI generation, remote upload, or
            modification of the original file.
          </p>
          <label className="daily-label">
            Draft
            <textarea
              value={draft}
              disabled={busy}
              placeholder={
                task === "Task list"
                  ? "Write your tasks and next steps…"
                  : task === "Project report"
                    ? "Write your progress, findings, and next steps…"
                    : "Write the decisions, owners, and next steps…"
              }
              onChange={(e) => {
                invalidate();
                setDraft(e.target.value);
              }}
            />
          </label>
          <label className="daily-label">
            Download filename
            <input
              value={filename}
              disabled={busy}
              maxLength={105}
              onChange={(e) => {
                invalidate();
                setFilename(e.target.value);
              }}
            />
          </label>
          <button
            className="daily-primary"
            disabled={busy || !draft.trim() || history.length >= MAX_HISTORY}
            onClick={() => void run("download")}
          >
            <Download size={17} />
            Guard & download draft
          </button>
          <small className="daily-help">
            Creates a new browser download. Nothing overwrites your source.
          </small>
        </article>
      </div>
      <div className={`daily-status ${check?.decision ?? ""}`} aria-live="polite">
        <strong>
          {check
            ? check.decision === "allow"
              ? "Allowed"
              : check.decision === "hold"
                ? audit.some((a) => a.id === check.record.id && a.completed && a.approved)
                  ? "Approved once · completed"
                  : "Human approval needed"
                : "Blocked by policy"
            : "Ready when you are"}
        </strong>
        <p>{notice}</p>
        {check && (
          <>
            <code>{check.record.pebble}</code>
            <p>
              {check.decision === "block"
                ? "This action targets a protected file class or falls outside the daily workspace policy."
                : check.decision === "hold"
                  ? "The model found this action unfamiliar in your recent workflow. Review it before approving."
                  : "The action fits this workspace policy and the model's expected workflow."}
            </p>
            <small>
              {check.model.calibrated ? "Empirical pilot calibration" : "Calibration pending"} ·
              Daily workspace policy ·{" "}
              {check.record.rules.length ? check.record.rules.join(", ") : "No hard rule flagged"}
            </small>
          </>
        )}
        {error && (
          <p role="alert" className="daily-error">
            {error}
          </p>
        )}
        {held && (
          <div className="daily-approval">
            <p>
              Approve only this {held.kind === "open" ? "local read" : "draft download"}. Editing
              the selection, draft, or filename cancels this approval.
            </p>
            <button disabled={busy} onClick={() => void approve()}>
              Approve this action once
            </button>
            <button
              disabled={busy}
              onClick={() => {
                setHeld(null);
                setCheck(null);
                setNotice("Held action cancelled. Run a new check to continue.");
              }}
            >
              Cancel
            </button>
          </div>
        )}
      </div>
      <p className="daily-help">
        Audit retains the last 64 checks, with completed and human-approved status. Held approval
        updates its original record. This is local decision metadata, not a tamper-evident hash
        chain; the Import audit tab can inspect its decisions.
      </p>
      <div className="daily-footer">
        <div>
          <button
            disabled={busy || !audit.length}
            onClick={() =>
              download(
                serializeDailyAudit(audit),
                "sentinel-workspace-audit.jsonl",
                "application/x-ndjson",
              )
            }
          >
            <Download size={16} />
            Download redacted audit ({audit.length}/64)
          </button>
          <button onClick={clear}>
            <Trash2 size={16} />
            Clear workspace
          </button>
        </div>
        <a
          href="https://github.com/YashAnand69/pebble-sentinel/blob/main/docs/DAILY_USE.md"
          target="_blank"
          rel="noreferrer"
        >
          Protect a local workflow: setup guide <ArrowUpRight size={16} />
        </a>
      </div>
    </section>
  );
}
