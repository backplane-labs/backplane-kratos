import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { create } from '@bufbuild/protobuf';
import { useClient } from '@backplane-labs/backplane-react';
import { usePlatformAction, usePlatformQuery } from '@backplane-labs/backplane-platform-ui';
import { ConfigServiceClient, GetConfigRequestSchema, SaveRevisionRequestSchema, ValidateOverrideRequestSchema, type ConfigViolation } from '@backplane-labs/backplane-api';
import { Badge, Button, Input, NativeSelect, Panel, Stack, StatusBadge, Switch, Textarea } from '@backplane-labs/backplane-ui';

/** A JSON value edited in place. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Obj = { [key: string]: Json };

const NS: Record<string, number> = { h: 3_600_000_000_000, m: 60_000_000_000, s: 1_000_000_000, ms: 1_000_000 };

/** Go's duration text of nanoseconds: 3600000000000 -> "1h". */
export function durationText(ns: number): string {
  if (!ns) return '0s';
  let rest = ns, out = '';
  for (const unit of ['h', 'm', 's', 'ms'] as const) {
    const n = Math.floor(rest / NS[unit]!);
    if (n) { out += `${n}${unit}`; rest -= n * NS[unit]!; }
  }
  return out || `${ns}ns`;
}

/** Nanoseconds of "1h30m", "45s", "250ms"; undefined when malformed. */
export function parseDuration(text: string): number | undefined {
  const t = text.trim();
  if (t === '0' || t === '0s') return 0;
  const re = /(\d+)(ms|h|m|s)/gy;
  let total = 0, m: RegExpExecArray | null, at = 0;
  while ((m = re.exec(t))) { total += Number(m[1]) * NS[m[2]!]!; at = re.lastIndex; }
  return at === t.length && at > 0 ? total : undefined;
}

export function getIn(obj: Json, path: string): Json | undefined {
  let cur: Json | undefined = obj;
  for (const key of path.split('.')) {
    if (cur === null || typeof cur !== 'object' || Array.isArray(cur)) return undefined;
    cur = (cur as Obj)[key];
  }
  return cur;
}

export function setIn(obj: Json, path: string, value: Json | undefined): Json {
  const [head, ...rest] = path.split('.');
  const base: Obj = obj !== null && typeof obj === 'object' && !Array.isArray(obj) ? { ...obj } : {};
  if (!rest.length) {
    if (value === undefined) delete base[head!]; else base[head!] = value;
    return base;
  }
  base[head!] = setIn(base[head!] ?? {}, rest.join('.'), value);
  return base;
}

/**
 * The live configuration of a service through the platform's ConfigService:
 * the effective values of its Live paths (from a live instance), a draft of
 * them, validation and saving as a revision (audited, rollback-able on the
 * service's Configuration page).
 */
export function useLiveConfig(service: string, durations: Record<string, readonly string[]> = {}) {
  const config = useClient(ConfigServiceClient);
  const state = usePlatformQuery(`config:${service}`, (signal) => config.getConfig(create(GetConfigRequestSchema, { service }), { signal }), { keep: true });
  const effective = useMemo(() => {
    const out: Record<string, Json> = {};
    const instance = state.value?.config?.instances.find((i) => i.live.length) ?? state.value?.config?.instances[0];
    for (const live of instance?.live ?? []) if (live.value) { try { out[live.path] = JSON.parse(live.value) as Json; } catch { /* not JSON */ } }
    return out;
  }, [state.value]);
  const [draft, setDraft] = useState<Record<string, Json>>({});
  const [touched, setTouched] = useState<Set<string>>(new Set());
  useEffect(() => { setDraft(effective); setTouched(new Set()); }, [effective]);
  const save = usePlatformAction<{ violations: ConfigViolation[]; revision?: bigint }>();
  const check = usePlatformAction<ConfigViolation[]>();
  const values = (paths: Iterable<string>) => {
    // A revision holds every override: keep the current ones, replace the touched.
    const out: Record<string, string> = { ...(state.value?.config?.current?.values ?? {}) };
    for (const path of paths) {
      // The effective configuration carries durations as nanoseconds; an
      // override names them ("1h30m").
      let value: Json = draft[path] ?? null;
      for (const field of durations[path] ?? []) {
        const v = getIn(value, field);
        if (typeof v === 'number') value = setIn(value, field, durationText(v));
      }
      out[path] = JSON.stringify(value);
    }
    return out;
  };
  return {
    loading: !state.value && state.error === undefined, error: state.error, revision: state.value?.config?.current?.revision,
    draft, touched, dirty: touched.size > 0,
    get: (path: string, field?: string) => field ? getIn(draft[path] ?? null, field) : draft[path],
    set: (path: string, field: string | undefined, value: Json | undefined) => {
      setDraft((d) => ({ ...d, [path]: field ? setIn(d[path] ?? {}, field, value) : (value ?? null) }));
      setTouched((t) => new Set(t).add(path));
    },
    reset: () => { setDraft(effective); setTouched(new Set()); },
    validate: () => check.run(async (signal) => (await config.validateOverride(create(ValidateOverrideRequestSchema, { service, values: values(touched) }), { signal })).violations),
    save: (comment: string) => save.run(async (signal) => {
      const res = await config.saveRevision(create(SaveRevisionRequestSchema, { service, values: values(touched), comment }), { signal });
      if (!res.violations.length) { setTouched(new Set()); state.refresh(); }
      return { violations: res.violations, revision: res.revision?.revision };
    }),
    check, saving: save, refresh: state.refresh,
  };
}

export type LiveConfig = ReturnType<typeof useLiveConfig>;

const muted = { color: 'var(--muted-foreground)', fontSize: 12 } as const;

/** One labelled row of a settings form. */
export function Row({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 240px) 1fr', gap: 12, alignItems: 'start', padding: '6px 0' }}>
    <div><div style={{ fontSize: 13 }}>{label}</div>{hint && <div style={muted}>{hint}</div>}</div><div>{children}</div>
  </div>;
}

export function Toggle({ cfg, path, field, label, hint }: { cfg: LiveConfig; path: string; field: string; label: string; hint?: ReactNode }) {
  return <Row label={label} hint={hint}><Switch aria-label={label} checked={cfg.get(path, field) === true} onCheckedChange={(v) => cfg.set(path, field, v)} /></Row>;
}

export function Text({ cfg, path, field, label, hint, placeholder }: { cfg: LiveConfig; path: string; field: string; label: string; hint?: ReactNode; placeholder?: string }) {
  const v = cfg.get(path, field);
  return <Row label={label} hint={hint}><Input aria-label={label} placeholder={placeholder} value={typeof v === 'string' ? v : ''}
    onChange={(e) => cfg.set(path, field, e.target.value || undefined)} /></Row>;
}

export function NumberField({ cfg, path, field, label, hint, min }: { cfg: LiveConfig; path: string; field: string; label: string; hint?: ReactNode; min?: number }) {
  const v = cfg.get(path, field);
  return <Row label={label} hint={hint}><Input aria-label={label} type="number" min={min} style={{ maxWidth: 160 }} value={typeof v === 'number' ? v : ''}
    onChange={(e) => cfg.set(path, field, e.target.value === '' ? undefined : Number(e.target.value))} /></Row>;
}

export function Duration({ cfg, path, field, label, hint }: { cfg: LiveConfig; path: string; field: string; label: string; hint?: ReactNode }) {
  const raw = cfg.get(path, field), v = typeof raw === 'string' ? parseDuration(raw) : typeof raw === 'number' ? raw : undefined;
  const [text, setText] = useState(v !== undefined ? durationText(v) : '');
  useEffect(() => { if (v !== undefined && parseDuration(text) !== v) setText(durationText(v)); }, [v]); // eslint-disable-line react-hooks/exhaustive-deps
  const bad = text !== '' && parseDuration(text) === undefined;
  return <Row label={label} hint={hint}><Stack direction="row" gap={8} style={{ alignItems: 'center' }}>
    <Input aria-label={label} aria-invalid={bad} style={{ maxWidth: 160 }} value={text} placeholder="1h30m"
      onChange={(e) => { setText(e.target.value); const ns = parseDuration(e.target.value); if (ns !== undefined) cfg.set(path, field, ns); }} />
    {bad && <span role="alert" style={{ ...muted, color: 'var(--destructive)' }}>1h, 30m, 45s, 250ms</span>}
  </Stack></Row>;
}

export function Choice({ cfg, path, field, label, hint, options }: { cfg: LiveConfig; path: string; field: string; label: string; hint?: ReactNode; options: readonly string[] }) {
  const v = cfg.get(path, field);
  return <Row label={label} hint={hint}><NativeSelect aria-label={label} value={typeof v === 'string' ? v : options[0]} onChange={(e) => cfg.set(path, field, e.target.value)}>
    {options.map((o) => <option key={o} value={o}>{o}</option>)}</NativeSelect></Row>;
}

/** A list of strings, one per line. */
export function Lines({ cfg, path, field, label, hint }: { cfg: LiveConfig; path: string; field: string; label: string; hint?: ReactNode }) {
  const v = cfg.get(path, field), list = Array.isArray(v) ? v.map(String) : [];
  const [text, setText] = useState(list.join('\n'));
  useEffect(() => { if (text.split('\n').map((s) => s.trim()).filter(Boolean).join('\n') !== list.join('\n')) setText(list.join('\n')); }, [v]); // eslint-disable-line react-hooks/exhaustive-deps
  return <Row label={label} hint={hint}><Textarea aria-label={label} rows={3} value={text} onChange={(e) => {
    setText(e.target.value); const next = e.target.value.split('\n').map((s) => s.trim()).filter(Boolean); cfg.set(path, field, next.length ? next : undefined);
  }} /></Row>;
}

/** The save bar: comment, validate, save, the violations. */
export function SaveBar({ cfg, labels }: { cfg: LiveConfig; labels: Record<'comment' | 'validate' | 'save' | 'saving' | 'reset' | 'valid' | 'saved' | 'unsaved' | 'revision', string> }) {
  const [comment, setComment] = useState('');
  const violations = cfg.saving.value?.violations.length ? cfg.saving.value.violations : cfg.check.value;
  return <Panel>
    <Stack gap={8}>
      <Stack direction="row" gap={8} style={{ alignItems: 'center', flexWrap: 'wrap' }}>
        {cfg.dirty ? <Badge variant="outline">{labels.unsaved}</Badge> : cfg.revision !== undefined && <span style={muted}>{labels.revision} {String(cfg.revision)}</span>}
        <Input aria-label={labels.comment} placeholder={labels.comment} value={comment} onChange={(e) => setComment(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
        <Button size="sm" variant="ghost" disabled={!cfg.dirty} onClick={cfg.reset}>{labels.reset}</Button>
        <Button size="sm" variant="outline" disabled={!cfg.dirty || cfg.check.pending} onClick={() => void cfg.validate()}>{labels.validate}</Button>
        <Button size="sm" disabled={!cfg.dirty || cfg.saving.pending} onClick={() => void cfg.save(comment).then(() => setComment(''))}>{cfg.saving.pending ? labels.saving : labels.save}</Button>
      </Stack>
      {violations && violations.length > 0 && <ul role="alert" style={{ margin: 0, paddingLeft: 18, color: 'var(--destructive)', fontSize: 12 }}>
        {violations.map((v, i) => <li key={i}><code>{v.path || '—'}</code> {v.message}{v.instance && <span style={muted}> ({v.instance})</span>}</li>)}</ul>}
      {cfg.check.value && !cfg.check.value.length && !cfg.saving.value && <StatusBadge tone="success">{labels.valid}</StatusBadge>}
      {cfg.saving.value && !cfg.saving.value.violations.length && <StatusBadge tone="success">{labels.saved} {String(cfg.saving.value.revision ?? '')}</StatusBadge>}
      {(cfg.saving.error ?? cfg.check.error) !== undefined && <span role="alert" style={{ color: 'var(--destructive)', fontSize: 12 }}>{String(cfg.saving.error ?? cfg.check.error)}</span>}
    </Stack>
  </Panel>;
}
