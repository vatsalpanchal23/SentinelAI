/**
 * Scan configuration.
 *
 * Every scan requires:
 *   - a syntactically valid target
 *   - the name of the person authorizing it
 *   - an explicit checkbox confirming written authorization exists
 *
 * The checkbox is not a formality — the server rejects any request that does
 * not include it. Scope defaults to the target and its subdomains, and can be
 * narrowed or extended.
 */

import { useState, type FormEvent } from "react";
import type { StartScanInput } from "@/lib/scan.functions";
import { PROFILES } from "@/lib/scanner/profiles";
import { AlertCircle, Play } from "lucide-react";

type Props = {
  onSubmit: (input: StartScanInput) => void;
  disabled: boolean;
};

export function ScanConfigForm({ onSubmit, disabled }: Props) {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<string>("quick");
  const [principal, setPrincipal] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [allowedDomains, setAllowedDomains] = useState("");
  const [excludedHosts, setExcludedHosts] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    const cleanTarget = target.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    if (!cleanTarget) return setError("Enter a target hostname.");
    if (!principal.trim()) return setError("Enter the name of the person or team authorizing this scan.");
    if (!confirmed) return setError("Confirm you have written authorization to test this target.");

    onSubmit({
      target: cleanTarget,
      profile,
      authorizationConfirmed: true,
      principal: principal.trim(),
      allowedDomains: allowedDomains.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean),
      allowedIps: [],
      excludedHosts: excludedHosts.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean),
    });
  };

  const active = PROFILES[profile] ?? PROFILES['quick']!;

  return (
    <form
      onSubmit={submit}
      data-testid="form-scan-config"
      className="scan-card flex flex-col gap-5 rounded-2xl border border-border/70 bg-card p-5 text-card-foreground sm:p-6 xl:sticky xl:top-24"
    >
      <div>
        <div className="mb-2 flex items-center justify-between"><h2 className="text-base font-extrabold tracking-tight">New assessment</h2><span className="rounded-full bg-primary/10 px-2 py-1 text-[9px] font-bold uppercase tracking-[0.12em] text-primary">Scoped</span></div>
        <p className="mt-1 text-xs text-muted-foreground">
          Only scan targets you are authorized to test. Every request is recorded with the authorizing principal and timestamp.
        </p>
      </div>

      <label className="flex flex-col gap-1.5 text-sm">
          <span className="text-xs font-bold uppercase tracking-[0.12em] text-muted-foreground">Target hostname</span>
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com"
          data-testid="input-target"
          className="rounded-xl border border-input bg-background px-3 py-2.5 text-sm outline-none transition focus:border-ring focus:ring-2 focus:ring-primary/15"
          spellCheck={false}
          autoComplete="off"
          disabled={disabled}
        />
        <span className="text-xs text-muted-foreground">
          Hostname only. Scope defaults to <code>example.com</code> and <code>*.example.com</code>.
        </span>
      </label>

      <label className="flex flex-col gap-1.5 text-sm">
          <span className="text-xs font-bold uppercase tracking-[0.12em] text-muted-foreground">Assessment profile</span>
        <select
          value={profile}
          onChange={(e) => setProfile(e.target.value)}
          data-testid="select-profile"
          className="rounded-xl border border-input bg-background px-3 py-2.5 text-sm outline-none transition focus:border-ring focus:ring-2 focus:ring-primary/15"
          disabled={disabled}
        >
          {Object.values(PROFILES).map((p) => (
            <option key={p.key} value={p.key}>{p.label}</option>
          ))}
        </select>
        <span className="text-xs text-muted-foreground">{active.description}</span>
      </label>

      <details className="rounded-md border border-border/60 bg-muted/20 p-3 text-sm">
        <summary data-testid="button-advanced-scope" className="cursor-pointer text-xs font-bold uppercase tracking-[0.1em] text-muted-foreground">Advanced scope</summary>
        <div className="mt-3 flex flex-col gap-3">
          <label className="flex flex-col gap-1 text-xs">
            <span>Allowed domains (overrides default)</span>
            <input
              value={allowedDomains}
              onChange={(e) => setAllowedDomains(e.target.value)}
              placeholder="example.com, *.example.com"
              data-testid="input-allowed-domains"
              className="rounded-lg border border-input bg-background px-2 py-1.5 text-sm outline-none focus:border-ring"
              disabled={disabled}
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span>Excluded hosts</span>
            <input
              value={excludedHosts}
              onChange={(e) => setExcludedHosts(e.target.value)}
              placeholder="mail.example.com, staging.example.com"
              data-testid="input-excluded-hosts"
              className="rounded-lg border border-input bg-background px-2 py-1.5 text-sm outline-none focus:border-ring"
              disabled={disabled}
            />
          </label>
        </div>
      </details>

      <label className="flex flex-col gap-1.5 text-sm">
        <span className="text-xs font-bold uppercase tracking-[0.12em] text-muted-foreground">Authorizing principal</span>
        <input
          value={principal}
          onChange={(e) => setPrincipal(e.target.value)}
          placeholder="Jane Smith, Acme Security"
          data-testid="input-principal"
          className="rounded-xl border border-input bg-background px-3 py-2.5 text-sm outline-none focus:border-ring focus:ring-2 focus:ring-primary/15"
          disabled={disabled}
        />
      </label>

      <label className="flex items-start gap-2 rounded-md border border-border/60 bg-muted/20 p-3 text-xs">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          data-testid="checkbox-authorization"
          className="mt-0.5 accent-primary"
          disabled={disabled}
        />
        <span>
          I confirm I have <strong>written authorization</strong> to perform a security assessment on this target,
          and that all scope rules above are correct.
        </span>
      </label>

      {error && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/60 bg-destructive/10 p-2 text-xs text-destructive">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <button
        type="submit"
        disabled={disabled}
        data-testid="button-start-assessment"
        className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-3 text-sm font-bold text-primary-foreground shadow-sm transition hover:bg-primary/90 disabled:cursor-wait disabled:opacity-60"
      >
        <Play className="h-4 w-4" />
        {disabled ? "Scanning…" : "Start assessment"}
      </button>
    </form>
  );
}
