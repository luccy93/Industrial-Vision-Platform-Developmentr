import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const AXIS_TICK = { fill: "#94a3b8", fontSize: 11 };

function shortLabel(iso: string, bucket: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  if (bucket === "hour") {
    return date.toLocaleString([], { month: "numeric", day: "numeric", hour: "numeric" });
  }
  return date.toLocaleDateString();
}

export function TrendChart({
  buckets,
  bucket,
  label,
}: {
  buckets: Array<{ bucket_start: string; count: number }>;
  bucket: string;
  label: string;
}) {
  const data = buckets.map((b) => ({ ...b, label: shortLabel(b.bucket_start, bucket) }));
  return (
    <figure>
      <LineChart width={640} height={260} data={data} role="img" aria-label={`${label} over time`}>
        <CartesianGrid stroke="#1e293b" />
        <XAxis dataKey="label" tick={AXIS_TICK} interval="preserveStartEnd" />
        <YAxis tick={AXIS_TICK} allowDecimals={false} />
        <Tooltip
          contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #334155" }}
          labelStyle={{ color: "#e2e8f0" }}
        />
        <Legend />
        <Line type="monotone" dataKey="count" name={label} stroke="#38bdf8" dot={false} />
      </LineChart>
      <figcaption className="mt-1 text-xs text-slate-500">
        {label} per {bucket}; UTC bucket boundaries, local-time labels.
      </figcaption>
    </figure>
  );
}

export function BreakdownBars({
  groups,
  label,
  horizontal = false,
}: {
  groups: Array<{ key: string; label: string; count: number }>;
  label: string;
  horizontal?: boolean;
}) {
  const data = groups.slice(0, 20);
  if (!horizontal) {
    return (
      <figure>
        <BarChart width={640} height={260} data={data} role="img" aria-label={label}>
          <CartesianGrid stroke="#1e293b" />
          <XAxis dataKey="label" tick={AXIS_TICK} interval={0} angle={-20} height={60} />
          <YAxis tick={AXIS_TICK} allowDecimals={false} />
          <Tooltip
            contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #334155" }}
            labelStyle={{ color: "#e2e8f0" }}
          />
          <Legend />
          <Bar dataKey="count" name={label} fill="#38bdf8" />
        </BarChart>
        <figcaption className="mt-1 text-xs text-slate-500">{label} (bounded top 20).</figcaption>
      </figure>
    );
  }
  return (
    <figure>
      <BarChart
        width={640}
        height={Math.max(120, data.length * 32)}
        data={data}
        layout="vertical"
        role="img"
        aria-label={label}
      >
        <CartesianGrid stroke="#1e293b" />
        <XAxis type="number" tick={AXIS_TICK} allowDecimals={false} />
        <YAxis type="category" dataKey="label" tick={AXIS_TICK} width={140} />
        <Tooltip
          contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #334155" }}
          labelStyle={{ color: "#e2e8f0" }}
        />
        <Legend />
        <Bar dataKey="count" name={label} fill="#34d399" />
      </BarChart>
      <figcaption className="mt-1 text-xs text-slate-500">{label} (bounded top 20).</figcaption>
    </figure>
  );
}
