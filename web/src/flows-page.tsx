import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { create } from '@bufbuild/protobuf';
import { timestampDate } from '@bufbuild/protobuf/wkt';
import { useClient } from '@backplane-labs/backplane-react';
import { usePluginContext } from '@backplane-labs/backplane-plugin-sdk';
import { ConnectionNotice, usePlatformAction, usePlatformQuery } from '@backplane-labs/backplane-platform-ui';
import { CodeEditor } from '@backplane-labs/backplane-editors';
import {
  Badge, Button, DetailDrawer, EmptyState, PageHeader, Panel, Skeleton, Stack, StatusBadge, Table, TableBody, TableCell, TableHead,
  TableHeader, TableRow, Timestamp,
} from '@backplane-labs/backplane-ui';
import { AdminServiceClient } from './gen/proto/kratos/console/v1/admin_ws_pb';
import { GetFlowsRequestSchema, TryFlowRequestSchema, type FlowCard, type FlowHook, type Finding, type TryFlowResponse } from './gen/proto/kratos/console/v1/admin_pb';
import { Choice, Duration, SaveBar, Text, Toggle, useLiveConfig, type LiveConfig } from './settings-kit';

const S = 'settings';
const mono = { fontFamily: 'var(--font-mono)' } as const;
const muted = { color: 'var(--muted-foreground)', fontSize: 12 } as const;
const durationFields = ['registration.lifespan', 'login.lifespan', 'settings.lifespan', 'settings.privileged_session_max_age', 'recovery.lifespan',
  'verification.lifespan', 'methods.code.lifespan', 'session.lifespan', 'session.earliest_possible_extend'] as const;

function useText() { return useTranslation('module.kratos').t; }

/** The console's Wiring page, next to this module's route. */
function wiringHref() {
  const at = window.location.pathname.indexOf('/s/');
  return (at >= 0 ? window.location.pathname.slice(0, at) : '') + '/wiring';
}

const tone = (level: string) => (level === 'error' ? 'danger' : level === 'warning' ? 'warning' : 'info');

function Findings({ findings }: { findings: Finding[] }) {
  const t = useText();
  if (!findings.length) return null;
  return <Stack gap={6}>{findings.map((f, i) => <div key={i} role={f.level === 'error' ? 'alert' : 'status'} style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 13 }}>
    <StatusBadge tone={tone(f.level)}>{t(`level_${f.level}`)}</StatusBadge><span>{f.text}{f.field && <span style={muted}> · {t('setting')} <code>{f.field}</code></span>}</span>
  </div>)}</Stack>;
}

/** Every self-service flow: what it does, where its UI is, its hooks, its event, what does not work. */
export function Flows() {
  const t = useText(), client = useClient(AdminServiceClient), cfg = useLiveConfig('kratos', { settings: durationFields });
  const flows = usePlatformQuery('kratos:flows', (signal) => client.getFlows(create(GetFlowsRequestSchema), { signal }), { keep: true });
  const [trying, setTrying] = useState<string>();
  // A saved revision reaches the service within a second or two: then the
  // findings describe it.
  const { refresh } = flows;
  useEffect(() => {
    if (cfg.revision === undefined) return undefined;
    const id = setTimeout(refresh, 2000);
    return () => clearTimeout(id);
  }, [cfg.revision]); // eslint-disable-line react-hooks/exhaustive-deps
  const labels = {
    comment: t('changeComment'), validate: t('validate'), save: t('saveRevision'), saving: t('saving'), reset: t('reset'),
    valid: t('valid'), saved: t('savedRevision'), unsaved: t('unsaved'), revision: t('revision'),
  };
  return <Stack gap={16}><ConnectionNotice />
    <PageHeader title={t('flowsTitle')} description={t('flowsDescription')}
      actions={<Stack direction="row" gap={8}><Button size="sm" variant="outline" asChild><a href={wiringHref()}>{t('openWiring')}</a></Button>
        <Button size="sm" variant="outline" onClick={() => { flows.refresh(); cfg.refresh(); }}>{t('refresh')}</Button></Stack>} />
    {flows.error !== undefined || cfg.error !== undefined ? <EmptyState role="alert" title={t('error')} />
      : !flows.value || cfg.loading ? <Stack gap={8} role="status" aria-label={t('loading')}><Skeleton style={{ height: 160 }} /><Skeleton style={{ height: 160 }} /></Stack>
      : <>
        {flows.value.findings.length > 0 && <Panel title={t('installationFindings')}><Findings findings={flows.value.findings} /></Panel>}
        {cfg.dirty && <SaveBar cfg={cfg} labels={labels} />}
        {flows.value.flows.map((card) => <Card key={card.flow} card={card} cfg={cfg} onTry={() => setTrying(card.flow)} />)}
        <SaveBar cfg={cfg} labels={labels} />
      </>}
    {trying && <TryDrawer flow={trying} onClose={() => setTrying(undefined)} />}
  </Stack>;
}

function Card({ card, cfg, onTry }: { card: FlowCard; cfg: LiveConfig; onTry: () => void }) {
  const t = useText(), f = card.flow;
  const switchable = f === 'registration' || f === 'recovery' || f === 'verification';
  const on = !switchable || cfg.get(S, `${f}.enabled`) === true;
  const worst = card.findings.some((x) => x.level === 'error') ? 'danger' : card.findings.some((x) => x.level === 'warning') ? 'warning' : undefined;
  return <Panel title={<Stack direction="row" gap={8} style={{ alignItems: 'center' }}><span>{t(`${f}Flow`)}</span>
    {on ? <StatusBadge tone="success">{t('on')}</StatusBadge> : <Badge variant="outline">{t('off')}</Badge>}
    {worst && <StatusBadge tone={worst}>{t('findingsCount', { count: card.findings.length })}</StatusBadge>}</Stack>}
    description={t(`${f}About`)}
    actions={<Button size="sm" variant="outline" disabled={f === 'settings' || !on} title={f === 'settings' ? t('trySettingsHint') : undefined} onClick={onTry}>{t('try')}</Button>}>
    <Stack gap={12}>
      <Findings findings={card.findings} />
      <div>
        {switchable && <Toggle cfg={cfg} path={S} field={`${f}.enabled`} label={t('enabled')} />}
        <Text cfg={cfg} path={S} field={`${f}.ui_url`} label={t('uiUrl')} hint={t('uiUrlHint')} />
        <Duration cfg={cfg} path={S} field={`${f}.lifespan`} label={t('lifespan')} hint={t('lifespanHint')} />
        {(f === 'recovery' || f === 'verification') && <Choice cfg={cfg} path={S} field={`${f}.use`} label={t('use')} options={['code', 'link']} />}
        {f === 'registration' && <><Toggle cfg={cfg} path={S} field="registration.login_after" label={t('loginAfter')} />
          <Toggle cfg={cfg} path={S} field="registration.show_verification_ui" label={t('showVerificationUi')} /></>}
        {f === 'login' && <><Toggle cfg={cfg} path={S} field="login.require_verified_address" label={t('requireVerified')} />
          <Toggle cfg={cfg} path={S} field="login.revoke_other_sessions" label={t('revokeOther')} /></>}
        {f === 'settings' && <Duration cfg={cfg} path={S} field="settings.privileged_session_max_age" label={t('privilegedAge')} hint={t('privilegedAgeHint')} />}
        {f === 'recovery' && <Toggle cfg={cfg} path={S} field="recovery.revoke_sessions" label={t('revokeAfterRecovery')} />}
      </div>
      <Table><TableHeader><TableRow><TableHead>{t('hookPoint')}</TableHead><TableHead>{t('state')}</TableHead><TableHead>{t('calls')}</TableHead>
        <TableHead>{t('last')}</TableHead><TableHead>{t('failOpen')}</TableHead></TableRow></TableHeader>
        <TableBody>{card.hooks.map((h) => <HookRow key={h.name} hook={h} cfg={cfg} />)}
          <TableRow><TableCell style={mono}>{card.event}</TableCell><TableCell colSpan={4} style={muted}>{t('eventRow')}</TableCell></TableRow>
        </TableBody></Table>
    </Stack>
  </Panel>;
}

function HookRow({ hook, cfg }: { hook: FlowHook; cfg: LiveConfig }) {
  const t = useText();
  const open = (cfg.get('fail_open') as string[] | null | undefined) ?? [];
  const checked = open.includes(hook.name);
  return <TableRow>
    <TableCell><Stack gap={2}><span style={mono}>kratos.{hook.name}</span><span style={muted}>{t(hook.when === 'before' ? 'beforeHint' : 'afterHint')}</span></Stack></TableCell>
    <TableCell>{hook.bound ? <StatusBadge tone="success">{t('isBound')}</StatusBadge> : <a href={wiringHref()} style={{ fontSize: 12 }}>{t('bindInWiring')}</a>}</TableCell>
    <TableCell>{String(hook.calls)}{hook.failures > 0n && <span style={{ color: 'var(--destructive)' }}> · {t('failures', { count: Number(hook.failures) })}</span>}</TableCell>
    <TableCell>{hook.lastAt ? <Stack gap={2}><Timestamp value={timestampDate(hook.lastAt)} /><span style={muted}>{hook.lastOutcome}</span></Stack> : '—'}</TableCell>
    <TableCell><input type="checkbox" aria-label={t('failOpen')} checked={checked} disabled={!hook.bound}
      onChange={(e) => cfg.set('fail_open', undefined, e.target.checked ? [...open, hook.name] : open.filter((x) => x !== hook.name))} /></TableCell>
  </TableRow>;
}

function TryDrawer({ flow, onClose }: { flow: string; onClose: () => void }) {
  const t = useText(), client = useClient(AdminServiceClient), { mode } = usePluginContext();
  const run = usePlatformQuery(`kratos:try:${flow}`, (signal) => client.tryFlow(create(TryFlowRequestSchema, { flow }), { signal }));
  const [raw, setRaw] = useState(false);
  const v: TryFlowResponse | undefined = run.value;
  const groups = v ? [...new Set(v.nodes.map((n) => n.group))] : [];
  const field = (n: TryFlowResponse['nodes'][number]): ReactNode => n.type === 'submit' ? <Badge variant="outline">{n.label || n.value || n.name}</Badge>
    : <span style={mono}>{n.name}</span>;
  return <DetailDrawer open onOpenChange={(o) => !o && onClose()} size="lg" title={t('tryTitle', { flow: t(`${flow}Flow`) })} description={t('tryDescription')}>
    {run.error !== undefined ? <EmptyState role="alert" title={t('error')} /> : !v ? <Stack role="status" aria-label={t('loading')}><Skeleton style={{ height: 120 }} /></Stack>
      : v.error ? <EmptyState role="alert" title={t('tryFailed')} description={v.error} />
      : <Stack gap={12}>
        {v.messages.map((m, i) => <p key={i} style={{ margin: 0 }}><StatusBadge tone="info">{m}</StatusBadge></p>)}
        {groups.map((g) => <Panel key={g} title={<Stack direction="row" gap={8}><span>{t('method')}</span><Badge variant="outline">{g}</Badge></Stack>} flush>
          <Table><TableHeader><TableRow><TableHead>{t('field')}</TableHead><TableHead>{t('type')}</TableHead><TableHead>{t('label')}</TableHead><TableHead /></TableRow></TableHeader>
            <TableBody>{v.nodes.filter((n) => n.group === g).map((n, i) => <TableRow key={i}>
              <TableCell>{field(n)}</TableCell><TableCell style={muted}>{n.type}{n.required && ` · ${t('required')}`}</TableCell>
              <TableCell>{n.label}</TableCell><TableCell style={{ ...muted, color: n.messages.length ? 'var(--destructive)' : undefined }}>{n.messages.join('; ')}</TableCell>
            </TableRow>)}</TableBody></Table>
        </Panel>)}
        <Button size="sm" variant="ghost" onClick={() => setRaw(!raw)}>{raw ? t('hideJson') : t('showJson')}</Button>
        {raw && <CodeEditor label={t('flowJson')} value={JSON.stringify(JSON.parse(v.flowJson || '{}'), null, 2)} language="json" mode={mode} readOnly height={360} />}
      </Stack>}
  </DetailDrawer>;
}
