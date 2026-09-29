import { Card } from "../components/ui/Card";

export default function Home() {
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold">Industrial AI Vision & Safety Intelligence — V01</h1>
      <p className="max-w-3xl text-sm text-slate-300">
        Foundation release: API skeleton, health probes, typed domain contracts, configuration,
        logging, Docker, and this platform shell. Live cameras, inference, tracking, and
        analytics arrive in later volumes.
      </p>
      <div className="grid gap-4 md:grid-cols-3">
        <Card title="Cameras">Camera monitoring coming in V02.</Card>
        <Card title="Incidents">Incident engine coming in a later volume.</Card>
        <Card title="Analytics">Analytics coming in a later volume.</Card>
      </div>
    </div>
  );
}
