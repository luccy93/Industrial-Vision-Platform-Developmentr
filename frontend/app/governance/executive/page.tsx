import { ExecutiveWorkspace } from "../../../components/governance/ExecutiveWorkspace";

export default function ExecutiveGovernancePage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-bold">Executive Governance Command Center</h1>
        <p className="text-xs text-slate-400">
          V38 decision support over V10–V37 records: deterministic executive health, source-preserving
          KPIs, compatible historical comparisons, advisory strategic actions, and bounded local
          reports. Missing data stays unavailable — it is never treated as zero. Nothing is emailed,
          published, or distributed externally.
        </p>
      </div>
      <ExecutiveWorkspace />
    </div>
  );
}
