import { WorkflowWorkspace } from "../../../components/governance/WorkflowWorkspace";

export default function WorkflowGovernancePage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-bold">Governance Workflow Orchestration</h1>
        <p className="text-xs text-slate-400">
          V39 coordination over V10–V38 records: versioned templates, persistent workflows,
          dependency-aware tasks, ownership history, read-only cross-domain references, deterministic
          SLA indicators, reasoned escalations, and append-only events. Missing due dates stay not
          applicable — they are never treated as zero time. Nothing is approved, released, deleted, or
          modified automatically.
        </p>
      </div>
      <WorkflowWorkspace />
    </div>
  );
}
