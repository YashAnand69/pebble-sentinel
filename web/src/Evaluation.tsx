import { useState } from "react";
import { ChevronDown } from "lucide-react";
type Json = Record<string, unknown>;
const record = (value: unknown): Json =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Json)
    : {};
const array = (value: unknown): Json[] =>
  Array.isArray(value) ? value.map(record) : [];
const number = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
const format = (value: unknown, digits = 2) =>
  number(value) === null ? "—" : Number(value).toFixed(digits);
const families = ["F1", "F2", "F3", "F4", "F5"];
const familyNames: Record<string, string> = {
  F1: "Injection and exfiltration",
  F2: "Malicious skill",
  F3: "Persistence and tampering",
  F4: "Destructive sweep",
  F5: "Slow-drip exfiltration",
};
export default function Evaluation({ data }: { data: Json }) {
  const [point, setPoint] = useState(1),
    [seed, setSeed] = useState(0);
  const runs = array(data.runs),
    run = runs[Math.min(seed, Math.max(0, runs.length - 1))] ?? {},
    operating = array(run.operating_points)[point] ?? {},
    trigram =
      array(record(data.baseline_trigram).operating_points)[point] ?? {},
    calibration = record(operating.calibration),
    dataset = record(data.data),
    benchmarkRun = runs.find(item => Object.keys(record(item.latency)).length > 0) ?? {},
    latency = record(benchmarkRun.latency),
    rollover = record(benchmarkRun.rollover_latency),
    hostedRun = runs.find(item => item.seed === 2026) ?? {},
    hostedPoints = array(hostedRun.operating_points),
    holdThreshold = record(record(hostedPoints[1]).calibration).threshold_bits,
    blockThreshold = record(record(hostedPoints[2]).calibration).threshold_bits;
  const rows = [
    { name: "B0 · Rules", metrics: record(data.baseline_rules) },
    { name: "B1 · Trigram", metrics: trigram },
    { name: "B2 · Transformer", metrics: record(operating.B2_model_only) },
    {
      name: "B3 · Model + rules",
      metrics: record(operating.B3_model_plus_rules),
    },
  ];
  const actualReport = Object.keys(record(data.baseline_rules)).length > 0;
  const aggregate = array(data.aggregate).filter(item => item.target_calibration_rate === calibration.target_false_alarm_rate);
  return (
    <div className="evaluation-content">
      {actualReport ? (
        <>
          <div className="benchmark-controls">
            <label>
              Calibration target
              <select
                value={point}
                onChange={(e) => setPoint(Number(e.target.value))}
              >
                <option value={0}>1% empirical tail</option>
                <option value={1}>0.1% empirical tail</option>
                <option value={2}>0.01% empirical tail</option>
              </select>
            </label>
            <label>
              Model seed
              <select
                value={seed}
                onChange={(e) => setSeed(Number(e.target.value))}
                disabled={!runs.length}
              >
                {runs.length ? (
                  runs.map((item, index) => (
                    <option key={index} value={index}>
                      {String(item.seed)}
                    </option>
                  ))
                ) : (
                  <option>Awaiting model run</option>
                )}
              </select>
            </label>
          </div>
          <div className="benchmark-scroll" tabIndex={0} role="region" aria-label="Measured benchmark comparison, scroll horizontally on small screens">
            <table className="benchmark-table">
              <caption>
                Flags before the harmful action in authored scenarios
              </caption>
              <thead>
                <tr>
                  <th scope="col">System</th>
                  {families.map((family) => (
                    <th key={family} scope="col" title={familyNames[family]}>
                      {family}
                    </th>
                  ))}
                  <th scope="col">
                    False alarms
                    <br />/ 1,000
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.name}>
                    <th scope="row">{row.name}</th>
                    {families.map((family) => {
                      const stats = record(
                        record(record(row.metrics.detection).families)[family],
                      );
                      return (
                        <td key={family} title={familyNames[family]}>
                          {number(stats.detected) !== null &&
                          number(stats.episodes) !== null
                            ? `${stats.detected}/${stats.episodes}`
                            : "—"}
                        </td>
                      );
                    })}
                    <td>{format(row.metrics.false_alarms_per_1000)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="benchmark-legend">
            F1 injection · F2 skill · F3 persistence · F4 destruction · F5 slow
            drip. Fractions are detected / authored episodes, not real-world
            attack coverage.
          </p>
          {aggregate.length > 0 && <div className="seed-aggregate"><span>False alarms / 1,000 across all model seeds</span>{aggregate.map(item => <p key={String(item.system)}><span>{item.system === "B2_model_only" ? "Transformer" : "Model + rules"}</span><strong>{format(item.false_alarms_per_1000_mean)} ± {format(item.false_alarms_per_1000_sample_std)}</strong></p>)}<small>Mean ± sample standard deviation on the same held-out synthetic workflows.</small></div>}
          <div className="calibration-caveat">
            <strong>Empirical targets are not guarantees.</strong>
            <p>
              {Number(dataset.calibration_actions ?? 0).toLocaleString()}{" "}
              calibration actions contain{" "}
              {String(
                dataset.distinct_calibration_context_action_pairs ??
                  "unreported",
              )}{" "}
              distinct context/action pairs and{" "}
              {String(dataset.unique_calibration_episodes ?? "unreported")}{" "}
              unique episodes. Repeated synthetic templates do not establish a
              0.01% future false-alarm rate.
            </p>
            {number(calibration.threshold_bits) !== null && (
              <span>
                Selected threshold {format(calibration.threshold_bits, 3)} bits
                · observed calibration flags{" "}
                {format(Number(calibration.observed_false_alarm_rate) * 100, 3)}
                %
              </span>
            )}
          </div>
          {number(holdThreshold) !== null && number(blockThreshold) !== null && <div className="hosted-thresholds"><span>Hosted seed 2026</span><div><span>Hold ≥ {format(holdThreshold,3)} bits</span><span>Block ≥ {format(blockThreshold,3)} bits</span></div>{holdThreshold === blockThreshold && <p>Hold and block thresholds coincide because the upper empirical quantiles are tied. No artificial gap is added.</p>}</div>}
          {Object.keys(latency).length > 0 && (
            <div className="latency-cards">
              <div>
                <span>Short episodes · p95</span>
                <strong>
                  {format(latency.p95_ms)} <small>ms</small>
                </strong>
                <p>
                  {Number(latency.actions ?? 0).toLocaleString()} calls · scorer
                  only
                </p>
              </div>
              <div>
                <span>Full 256-token window · p95</span>
                <strong>
                  {format(rollover.p95_ms)} <small>ms</small>
                </strong>
                <p>
                  {Number(rollover.actions ?? 0).toLocaleString()} calls ·
                  scorer only
                </p>
              </div>
            </div>
          )}
          <p className="control-note">
            Latency was measured on seed {String(benchmarkRun.seed ?? "unreported")}. It excludes encoding, policy and audit. Full-window behavior
            matters for mature sessions. The under-5-ms end-to-end target is not
            established by a short-episode scorer benchmark.
          </p>
          <p className="control-note">
            {runs.length} model seeds ·{" "}
            {Number(dataset.test_actions ?? 0).toLocaleString()} held-out benign
            actions. Seeds reuse the same synthetic benchmark; they are not
            independent security trials.
          </p>
        </>
      ) : (
        <p className="control-note">
          The service returned an evaluation report. Inspect the complete
          artifact below for its measured values.
        </p>
      )}
      <details>
        <summary>
          Inspect the complete measured report <ChevronDown size={13} />
        </summary>
        <pre>{JSON.stringify(data, null, 2)}</pre>
      </details>
      <p className="control-note">
        Synthetic workflows and team-authored attacks are preliminary evidence.
        See the data card and evaluation protocol for limitations and unrun
        experiments.
      </p>
    </div>
  );
}
