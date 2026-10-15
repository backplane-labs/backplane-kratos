import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { create } from '@bufbuild/protobuf';
import { timestampDate, type Timestamp as PbTimestamp } from '@bufbuild/protobuf/wkt';
import { useClient } from '@backplane-labs/backplane-react';
import { definePlugin, usePluginContext, usePluginNavigate } from '@backplane-labs/backplane-plugin-sdk';
import { ConnectionNotice, usePlatformAction, usePlatformQuery } from '@backplane-labs/backplane-platform-ui';
import { CodeEditor, type EditorDiagnostic } from '@backplane-labs/backplane-editors';
import {
  Badge, Button, ClipboardButton, ConfirmAction, DetailDrawer, EmptyState, Input, KeyValueList, NativeSelect, PageHeader, Panel, SearchInput,
  SecretInput, Skeleton, Stack, StatRow, StatTile, StatusBadge, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Timestamp,
} from '@backplane-labs/backplane-ui';
import { AdminServiceClient } from './gen/proto/kratos/console/v1/admin_ws_pb';
import {
  CreateIdentityRequestSchema, CreateRecoveryCodeRequestSchema, ExtendSessionRequestSchema, ImportIdentitiesRequestSchema, SetAddressVerifiedRequestSchema, DeleteCredentialsRequestSchema, DeleteIdentityRequestSchema, GetIdentityRequestSchema,
  GetMessageRequestSchema, GetOverlayRequestSchema, GetStatusRequestSchema, ListIdentitiesRequestSchema, ListMessagesRequestSchema, ListSchemasRequestSchema,
  ListSessionsRequestSchema, RevokeSessionsRequestSchema, UpdateIdentityRequestSchema,
  type CreateRecoveryCodeResponse, type Identity, type ImportResult, type Message, type Schema, type Session,
} from './gen/proto/kratos/console/v1/admin_pb';
import navigation from './navigation';
import { Settings } from './settings';
import { Flows } from './flows-page';

const mono = { fontFamily: 'var(--font-mono)' } as const;
const muted = { color: 'var(--muted-foreground)', fontSize: 12 } as const;
const date = (value?: PbTimestamp) => value ? timestampDate(value) : undefined;
function useText() { return useTranslation('module.kratos').t; }

function Loading() {
  const t = useText();
  return <Stack gap={8} style={{ padding: 12 }} role="status" aria-label={t('loading')}><Skeleton style={{ height: 28 }} /><Skeleton style={{ height: 28 }} /></Stack>;
}

function Failure({ error }: { error: unknown }) {
  const t = useText();
  return <EmptyState role="alert" title={t('error')} description={error instanceof Error ? error.message : String(error)} />;
}

function Header({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) {
  const t = useText(), context = usePluginContext();
  return <PageHeader title={title} description={description} meta={<Badge variant="outline">{t(context.environment)}</Badge>} actions={actions} />;
}

/** The installation: Kratos, the overlay, every hook point and its callbacks. */
function Overview() {
  const t = useText(), client = useClient(AdminServiceClient), { mode } = usePluginContext();
  const [tick, setTick] = useState(0);
  useEffect(() => { const id = setInterval(() => setTick((n) => n + 1), 10_000); return () => clearInterval(id); }, []);
  const status = usePlatformQuery(`kratos:status:${tick}`, (signal) => client.getStatus(create(GetStatusRequestSchema), { signal }), { keep: true });
  const overlay = usePlatformQuery(`kratos:overlay:${tick}`, (signal) => client.getOverlay(create(GetOverlayRequestSchema), { signal }), { keep: true });
  const s = status.value;
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('overviewTitle')} description={t('overviewDescription')}
      actions={<Button variant="outline" size="sm" onClick={() => { status.refresh(); overlay.refresh(); }}>{t('refresh')}</Button>} />
    {status.error !== undefined ? <Failure error={status.error} /> : !s ? <Loading /> : <>
      {s.problem && <p role="alert" style={{ margin: 0 }}><StatusBadge tone="danger">{t('kratosDown')}</StatusBadge> <span style={{ fontSize: 13 }}>{s.problem}</span></p>}
      {s.overlay?.error && <p role="alert" style={{ margin: 0 }}><StatusBadge tone="danger">{t('overlayRejected')}</StatusBadge> <span style={{ fontSize: 13 }}>{s.overlay.error}</span></p>}
      <StatRow>
        <StatTile label={t('kratos')} value={s.version || '—'} tone={s.problem ? 'danger' : 'success'} hint={<span style={mono}>{s.adminUrl}</span>} />
        <StatTile label={t('overlay')} value={s.overlay?.path ? (s.overlay.hash || '—') : t('snippets')}
          hint={s.overlay?.path ? <>{s.overlay.path} · <Timestamp value={date(s.overlay.writtenAt)} /></> : t('snippetsHint')} />
        <StatTile label={t('bound')} value={`${s.hooks.filter((h) => h.bound).length} / ${s.hooks.length}`} hint={t('boundHint')} />
        <StatTile label={t('events')} value={s.events ? t('on') : t('off')} hint={t('eventsHint')} />
      </StatRow>
      <Panel title={t('hooks')} count={s.hooks.length} flush footer={<span style={muted}>{t('hooksFooter')}</span>}>
        <Table><TableHeader><TableRow><TableHead>{t('hook')}</TableHead><TableHead>{t('state')}</TableHead><TableHead>{t('meaning')}</TableHead></TableRow></TableHeader>
          <TableBody>{s.hooks.map((h) => <TableRow key={h.name}>
            <TableCell style={mono}>kratos.{h.name}</TableCell>
            <TableCell><Stack direction="row" gap={4}>{h.bound ? <StatusBadge tone="success">{t('isBound')}</StatusBadge> : <Badge variant="outline">{t('unbound')}</Badge>}
              {h.failOpen && <Badge variant="outline" title={t('failOpenHint')}>{t('failOpen')}</Badge>}</Stack></TableCell>
            <TableCell style={muted}>{h.description}</TableCell>
          </TableRow>)}</TableBody></Table>
      </Panel>
      <Panel title={t('callbacks')} count={s.callbacks.length} flush description={<span style={mono}>{s.callbacksUrl}</span>}>
        {!s.callbacks.length ? <EmptyState title={t('noCallbacks')} /> : <Table>
          <TableHeader><TableRow><TableHead>{t('point')}</TableHead><TableHead>{t('calls')}</TableHead><TableHead>{t('last')}</TableHead><TableHead>{t('outcome')}</TableHead></TableRow></TableHeader>
          <TableBody>{s.callbacks.map((c) => <TableRow key={c.point}>
            <TableCell style={mono}>{c.point}</TableCell>
            <TableCell>{String(c.calls)}{c.failures > 0n && <span style={{ color: 'var(--destructive)' }}> · {t('failures', { count: Number(c.failures) })}</span>}</TableCell>
            <TableCell><Timestamp value={date(c.lastAt)} /> <span style={muted}>{c.lastLatencyMs.toFixed(1)} ms</span></TableCell>
            <TableCell><Badge variant="outline">{c.lastOutcome}</Badge> {c.lastError && <span style={{ ...muted, color: 'var(--destructive)' }}>{c.lastError}</span>}</TableCell>
          </TableRow>)}</TableBody></Table>}
      </Panel>
      <Panel title={t('overlayContent')} description={t('overlayContentHint')}>
        {overlay.value?.error ? <p role="alert" style={{ margin: 0, color: 'var(--destructive)' }}>{overlay.value.error}</p>
          : <CodeEditor label={t('overlayContent')} value={overlay.value?.content ?? ''} language="yaml" mode={mode} readOnly height={360} />}
      </Panel>
    </>}
  </Stack>;
}

// ——— identities ———

/** Keys and required keys of a schema's traits. */
function traitsOf(schema?: Schema): { keys: string[]; required: string[]; scaffold: string } {
  try {
    const doc = JSON.parse(schema?.schemaJson ?? '{}') as { properties?: { traits?: { properties?: Record<string, { type?: string }>; required?: string[] } } };
    const props = doc.properties?.traits?.properties ?? {}, required = doc.properties?.traits?.required ?? [];
    const scaffold = Object.fromEntries(Object.entries(props).filter(([k]) => required.includes(k) || Object.keys(props).length <= 4)
      .map(([k, v]) => [k, v.type === 'object' ? {} : v.type === 'boolean' ? false : v.type === 'number' || v.type === 'integer' ? 0 : '']));
    return { keys: Object.keys(props), required, scaffold: JSON.stringify(scaffold, null, 2) };
  } catch { return { keys: [], required: [], scaffold: '{}' }; }
}

/** A JSON editor of traits: scaffolded, completed and checked from the identity schema. */
function TraitsEditor({ label, value, onChange, schema, readOnly }: { label: string; value: string; onChange?: (v: string) => void; schema?: Schema; readOnly?: boolean }) {
  const t = useText(), { mode } = usePluginContext(), traits = useMemo(() => traitsOf(schema), [schema]);
  return <CodeEditor label={label} value={value} onChange={onChange} language="json" mode={mode} height={200} readOnly={readOnly}
    complete={async ({ value: text, position }) => {
      const before = text.slice(0, position), quote = before.lastIndexOf('"');
      if (quote < 0 || /[:,]\s*"[^"]*$/.test(before) === false && !/[{,]\s*"[^"]*$/.test(before)) return null;
      return traits.keys.map((key) => ({ label: key, apply: key, detail: traits.required.includes(key) ? t('required') : undefined }));
    }}
    validate={async (text) => {
      const out: EditorDiagnostic[] = [];
      let parsed: unknown;
      try { parsed = JSON.parse(text || '{}'); } catch (e) { return [{ from: 0, to: text.length, severity: 'error', message: e instanceof Error ? e.message : String(e) }]; }
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return [{ from: 0, to: text.length, severity: 'error', message: t('traitsObject') }];
      for (const key of traits.required) if (!(key in parsed)) out.push({ from: 0, to: Math.min(1, text.length), severity: 'error', message: t('traitsMissing', { key }) });
      for (const key of Object.keys(parsed)) if (traits.keys.length && !traits.keys.includes(key)) {
        const at = text.indexOf(`"${key}"`); out.push({ from: Math.max(0, at), to: Math.max(0, at) + key.length + 2, severity: 'warning', message: t('traitsUnknown', { key }) });
      }
      return out;
    }} />;
}

function useSchemas() {
  const client = useClient(AdminServiceClient);
  return usePlatformQuery('kratos:schemas', (signal) => client.listSchemas(create(ListSchemasRequestSchema), { signal }), { keep: true });
}

function Identities() {
  const t = useText(), client = useClient(AdminServiceClient);
  const [query, setQuery] = useState(''), [applied, setApplied] = useState(''), [pages, setPages] = useState<string[]>(['']), [open, setOpen] = useState<string>(), [creating, setCreating] = useState(false);
  const page = pages[pages.length - 1] ?? '';
  useEffect(() => { const id = setTimeout(() => { setApplied(query.trim()); setPages(['']); }, 300); return () => clearTimeout(id); }, [query]);
  const list = usePlatformQuery(`kratos:identities:${applied}:${page}`, (signal) => client.listIdentities(create(ListIdentitiesRequestSchema, { query: applied, pageToken: page, pageSize: 50 }), { signal }), { keep: true });
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('identitiesTitle')} description={t('identitiesDescription')}
      actions={<Stack direction="row" gap={8}><Button size="sm" onClick={() => setCreating(true)}>{t('newIdentity')}</Button><Button variant="outline" size="sm" onClick={list.refresh}>{t('refresh')}</Button></Stack>} />
    <SearchInput value={query} onValueChange={setQuery} label={t('search')} placeholder={t('searchHint')} />
    <Panel title={t('identities')} count={list.value?.identities.length} flush footer={<Stack direction="row" gap={8} style={{ alignItems: 'center' }}>
      <Button size="sm" variant="outline" disabled={pages.length < 2} onClick={() => setPages(pages.slice(0, -1))}>{t('previous')}</Button>
      <Button size="sm" variant="outline" disabled={!list.value?.nextPageToken} onClick={() => list.value && setPages([...pages, list.value.nextPageToken])}>{t('next')}</Button>
      <span style={muted}>{t('auditNote')}</span></Stack>}>
      {list.error !== undefined ? <Failure error={list.error} /> : !list.value ? <Loading /> : !list.value.identities.length ? <EmptyState title={applied ? t('noMatch') : t('noIdentities')} />
        : <Table><TableHeader><TableRow><TableHead>{t('identity')}</TableHead><TableHead>{t('schema')}</TableHead><TableHead>{t('state')}</TableHead><TableHead>{t('verified')}</TableHead><TableHead>{t('created')}</TableHead></TableRow></TableHeader>
          <TableBody>{list.value.identities.map((i) => <TableRow key={i.id} style={{ cursor: 'pointer' }} onClick={() => setOpen(i.id)}>
            <TableCell><Stack gap={2}><span>{i.label}</span><span style={{ ...muted, ...mono }}>{i.id}</span></Stack></TableCell>
            <TableCell><Badge variant="outline">{i.schemaId}</Badge></TableCell>
            <TableCell><StateBadge state={i.state} /></TableCell>
            <TableCell>{i.verifiableAddresses.length ? (i.verifiableAddresses.every((a) => a.verified) ? <StatusBadge tone="success">{t('yes')}</StatusBadge> : <Badge variant="outline">{t('no')}</Badge>) : '—'}</TableCell>
            <TableCell><Timestamp value={date(i.createdAt)} /></TableCell>
          </TableRow>)}</TableBody></Table>}
    </Panel>
    {open && <IdentityCard id={open} onClose={() => setOpen(undefined)} onChanged={list.refresh} />}
    {creating && <CreateIdentity onClose={() => setCreating(false)} onCreated={(id) => { setCreating(false); list.refresh(); setOpen(id); }} />}
  </Stack>;
}

function StateBadge({ state }: { state: string }) {
  const t = useText();
  return state === 'inactive' ? <StatusBadge tone="warning">{t('inactive')}</StatusBadge> : <StatusBadge tone="success">{t('active')}</StatusBadge>;
}

function ActionError({ error }: { error: unknown }) {
  if (error === undefined) return null;
  return <span role="alert" style={{ color: 'var(--destructive)', fontSize: 12 }}>{error instanceof Error ? error.message : String(error)}</span>;
}

/** An empty JSON object is no metadata. */
const unset = (json: string) => json.replace(/\s/g, '') === '{}' ? '' : json;

function IdentityCard({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const t = useText(), client = useClient(AdminServiceClient), schemas = useSchemas();
  const card = usePlatformQuery(`kratos:identity:${id}`, (signal) => client.getIdentity(create(GetIdentityRequestSchema, { id }), { signal }));
  const identity = card.value?.identity;
  const [traits, setTraits] = useState(''), [metaPublic, setMetaPublic] = useState(''), [metaAdmin, setMetaAdmin] = useState('');
  const { mode } = usePluginContext();
  useEffect(() => {
    if (!identity) return;
    const pretty = (s: string) => s ? JSON.stringify(JSON.parse(s), null, 2) : '{}';
    setTraits(pretty(identity.traitsJson)); setMetaPublic(pretty(identity.metadataPublicJson)); setMetaAdmin(pretty(identity.metadataAdminJson));
  }, [identity]);
  const save = usePlatformAction<void>(), state = usePlatformAction<void>(), recovery = usePlatformAction<CreateRecoveryCodeResponse>();
  const [expiresIn, setExpiresIn] = useState(''), [flowType, setFlowType] = useState('browser');
  const schema = schemas.value?.schemas.find((s) => s.id === identity?.schemaId);
  const update = (patch: { state?: string }) => async (signal: AbortSignal) => {
    if (!identity) return;
    await client.updateIdentity(create(UpdateIdentityRequestSchema, {
      id, schemaId: identity.schemaId, traitsJson: traits, state: patch.state ?? identity.state, metadataPublicJson: unset(metaPublic), metadataAdminJson: unset(metaAdmin),
    }), { signal });
    card.refresh(); onChanged();
  };
  return <DetailDrawer open onOpenChange={(o) => !o && onClose()} size="lg" title={identity?.label ?? t('loading')} description={<span style={mono}>{id}</span>}
    actions={identity && <ConfirmAction trigger={<Button size="sm" variant="destructive">{t('delete')}</Button>} title={t('deleteTitle')} description={t('deleteDescription', { label: identity.label })}
      confirmLabel={t('delete')} onConfirm={async (signal) => { await client.deleteIdentity(create(DeleteIdentityRequestSchema, { id }), { signal }); onChanged(); onClose(); }} />}>
    {card.error !== undefined ? <Failure error={card.error} /> : !identity ? <Loading /> : <Stack gap={16}>
      <KeyValueList items={[
        { label: t('schema'), value: <Badge variant="outline">{identity.schemaId}</Badge> },
        { label: t('state'), value: <Stack direction="row" gap={8} style={{ alignItems: 'center' }}><StateBadge state={identity.state} />
          <Button size="sm" variant="outline" disabled={state.pending} onClick={() => void state.run(update({ state: identity.state === 'inactive' ? 'active' : 'inactive' }))}>
            {identity.state === 'inactive' ? t('activate') : t('deactivate')}</Button><ActionError error={state.error} /></Stack> },
        { label: t('externalId'), value: identity.externalId || '—' },
        { label: t('created'), value: <Timestamp value={date(identity.createdAt)} absolute /> },
        { label: t('updated'), value: <Timestamp value={date(identity.updatedAt)} absolute /> },
      ]} />
      <Panel title={t('traits')} actions={<Stack direction="row" gap={8} style={{ alignItems: 'center' }}><ActionError error={save.error} />
        <Button size="sm" disabled={save.pending} onClick={() => void save.run(update({}))}>{save.pending ? t('saving') : t('save')}</Button></Stack>}>
        <Stack gap={12}>
          <TraitsEditor label={t('traits')} value={traits} onChange={setTraits} schema={schema} />
          <CodeEditor label={t('metadataPublic')} value={metaPublic} onChange={setMetaPublic} language="json" mode={mode} height={100} />
          <CodeEditor label={t('metadataAdmin')} value={metaAdmin} onChange={setMetaAdmin} language="json" mode={mode} height={100} />
        </Stack>
      </Panel>
      <Panel title={t('addresses')} flush>
        {!identity.verifiableAddresses.length ? <EmptyState title={t('noAddresses')} /> : <Table><TableBody>{identity.verifiableAddresses.map((a) => <TableRow key={a.value}>
          <TableCell style={mono}>{a.value}</TableCell><TableCell><Badge variant="outline">{a.via}</Badge></TableCell>
          <TableCell>{a.verified ? <StatusBadge tone="success">{t('verified')}</StatusBadge> : <Badge variant="outline">{a.status}</Badge>}</TableCell>
          <TableCell style={{ textAlign: 'right' }}><ConfirmAction trigger={<Button size="sm" variant="outline">{a.verified ? t('markUnverified') : t('markVerified')}</Button>}
            title={a.verified ? t('markUnverifiedTitle') : t('markVerifiedTitle')} description={t('markDescription', { address: a.value })} confirmLabel={a.verified ? t('markUnverified') : t('markVerified')}
            onConfirm={async (signal) => { await client.setAddressVerified(create(SetAddressVerifiedRequestSchema, { id, value: a.value, verified: !a.verified }), { signal }); card.refresh(); }} /></TableCell></TableRow>)}</TableBody></Table>}
      </Panel>
      <Panel title={t('credentials')} flush footer={<span style={muted}>{t('credentialsHint')}</span>}>
        {!identity.credentials.length ? <EmptyState title={t('noCredentials')} /> : <Table><TableBody>{identity.credentials.map((c) => <TableRow key={c.type}>
          <TableCell><Badge variant="outline">{c.type}</Badge></TableCell><TableCell style={mono}>{c.identifiers.join(', ')}</TableCell>
          <TableCell style={{ textAlign: 'right' }}>{['password', 'code'].includes(c.type) ? null : <ConfirmAction trigger={<Button size="sm" variant="outline">{t('remove')}</Button>}
            title={t('removeCredentialTitle', { type: c.type })} description={t('removeCredentialDescription')} confirmLabel={t('remove')}
            onConfirm={async (signal) => { await client.deleteCredentials(create(DeleteCredentialsRequestSchema, { id, type: c.type, identifier: c.type === 'oidc' || c.type === 'saml' ? c.identifiers[0] ?? '' : '' }), { signal }); card.refresh(); }} />}</TableCell>
        </TableRow>)}</TableBody></Table>}
      </Panel>
      <Panel title={t('sessions')} count={card.value?.sessions.length} flush actions={card.value?.sessions.some((s) => s.active) &&
        <ConfirmAction trigger={<Button size="sm" variant="outline">{t('revokeAll')}</Button>} title={t('revokeAllTitle')} description={t('revokeAllDescription')} confirmLabel={t('revokeAll')}
          onConfirm={async (signal) => { await client.revokeSessions(create(RevokeSessionsRequestSchema, { identityId: id }), { signal }); card.refresh(); }} />}>
        <SessionTable sessions={card.value?.sessions ?? []} onChanged={card.refresh} owner={false} />
      </Panel>
      <Panel title={t('recovery')} description={t('recoveryHint')}>
        <Stack gap={8}>
          <Stack direction="row" gap={8}>
            <Input aria-label={t('expiresIn')} placeholder={t('expiresInHint')} value={expiresIn} onChange={(e) => setExpiresIn(e.target.value)} style={{ width: 160 }} />
            <NativeSelect aria-label={t('flowType')} value={flowType} onChange={(e) => setFlowType(e.target.value)}><option value="browser">{t('flowBrowser')}</option><option value="api">{t('flowApi')}</option></NativeSelect>
            <Button size="sm" variant="outline" disabled={recovery.pending} onClick={() => void recovery.run((signal) => client.createRecoveryCode(create(CreateRecoveryCodeRequestSchema, { id, expiresIn, flowType }), { signal }))}>{t('recoveryCode')}</Button>
            <Button size="sm" variant="outline" disabled={recovery.pending} onClick={() => void recovery.run((signal) => client.createRecoveryCode(create(CreateRecoveryCodeRequestSchema, { id, link: true, expiresIn }), { signal }))}>{t('recoveryLink')}</Button>
            <ActionError error={recovery.error} />
          </Stack>
          {recovery.value && <KeyValueList items={[
            ...(recovery.value.code ? [{ label: t('code'), value: <Stack direction="row" gap={8} style={{ alignItems: 'center' }}><span style={mono}>{recovery.value.code}</span><ClipboardButton value={recovery.value.code} /></Stack> }] : []),
            { label: t('link'), value: <Stack direction="row" gap={8} style={{ alignItems: 'center' }}><span style={{ ...mono, wordBreak: 'break-all' }}>{recovery.value.link}</span><ClipboardButton value={recovery.value.link} /></Stack> },
            { label: t('expires'), value: <Timestamp value={date(recovery.value.expiresAt)} absolute /> },
          ]} />}
        </Stack>
      </Panel>
    </Stack>}
  </DetailDrawer>;
}

function CreateIdentity({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const t = useText(), client = useClient(AdminServiceClient), schemas = useSchemas(), create_ = usePlatformAction<string>();
  const [schemaId, setSchemaId] = useState(''), [traits, setTraits] = useState(''), [password, setPassword] = useState('');
  const [externalId, setExternalId] = useState(''), [inactive, setInactive] = useState(false), [metaPublic, setMetaPublic] = useState('{}'), [metaAdmin, setMetaAdmin] = useState('{}');
  const { mode } = usePluginContext();
  const list = schemas.value?.schemas ?? [], schema = list.find((s) => s.id === schemaId) ?? list[0];
  useEffect(() => { if (schema && !schemaId) { setSchemaId(schema.id); setTraits(traitsOf(schema).scaffold); } }, [schema, schemaId]);
  return <DetailDrawer open onOpenChange={(o) => !o && onClose()} title={t('newIdentity')} description={t('newIdentityHint')}>
    {schemas.error !== undefined ? <Failure error={schemas.error} /> : !schemas.value ? <Loading /> : <Stack gap={12}>
      <label style={muted}>{t('schema')}</label>
      <NativeSelect aria-label={t('schema')} value={schemaId} onChange={(e) => { setSchemaId(e.target.value); setTraits(traitsOf(list.find((s) => s.id === e.target.value)).scaffold); }}>
        {list.map((s) => <option key={s.id} value={s.id}>{s.id}</option>)}
      </NativeSelect>
      <TraitsEditor label={t('traits')} value={traits} onChange={setTraits} schema={schema} />
      <SecretInput label={t('passwordOptional')} value={password} onValueChange={setPassword} />
      <Input aria-label={t('externalId')} placeholder={t('externalIdHint')} value={externalId} onChange={(e) => setExternalId(e.target.value)} />
      <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}><input type="checkbox" checked={inactive} onChange={(e) => setInactive(e.target.checked)} />{t('createInactive')}</label>
      <CodeEditor label={t('metadataPublic')} value={metaPublic} onChange={setMetaPublic} language="json" mode={mode} height={90} />
      <CodeEditor label={t('metadataAdmin')} value={metaAdmin} onChange={setMetaAdmin} language="json" mode={mode} height={90} />
      <Stack direction="row" gap={8} style={{ alignItems: 'center' }}>
        <Button size="sm" disabled={create_.pending || !schemaId} onClick={() => void create_.run(async (signal) => {
          const res = await client.createIdentity(create(CreateIdentityRequestSchema, {
            schemaId, traitsJson: traits, password, externalId, state: inactive ? 'inactive' : 'active', metadataPublicJson: unset(metaPublic), metadataAdminJson: unset(metaAdmin),
          }), { signal });
          onCreated(res.identity?.id ?? ''); return res.identity?.id ?? '';
        })}>{create_.pending ? t('creating') : t('create')}</Button>
        <ActionError error={create_.error} />
      </Stack>
    </Stack>}
  </DetailDrawer>;
}

function SessionTable({ sessions, onChanged, owner }: { sessions: Session[]; onChanged: () => void; owner: boolean }) {
  const t = useText(), client = useClient(AdminServiceClient);
  if (!sessions.length) return <EmptyState title={t('noSessions')} />;
  return <Table><TableHeader><TableRow>{owner && <TableHead>{t('identity')}</TableHead>}<TableHead>{t('session')}</TableHead><TableHead>{t('methods')}</TableHead><TableHead>{t('device')}</TableHead><TableHead>{t('expires')}</TableHead><TableHead /></TableRow></TableHeader>
    <TableBody>{sessions.map((s) => <TableRow key={s.id}>
      {owner && <TableCell>{s.identityLabel || <span style={mono}>{s.identityId}</span>}</TableCell>}
      <TableCell><Stack gap={2}>{s.active ? <StatusBadge tone="success">{t('active')}</StatusBadge> : <Badge variant="outline">{t('ended')}</Badge>}<span style={{ ...muted, ...mono }}>{s.id}</span></Stack></TableCell>
      <TableCell><Stack direction="row" gap={4}>{s.methods.map((m) => <Badge key={m} variant="outline">{m}</Badge>)}<span style={muted}>{s.aal}</span></Stack></TableCell>
      <TableCell style={muted}>{s.devices.map((d) => [d.ipAddress, d.location, d.userAgent].filter(Boolean).join(' · ')).join('; ') || '—'}</TableCell>
      <TableCell><Timestamp value={date(s.expiresAt)} /></TableCell>
      <TableCell style={{ textAlign: 'right' }}>{s.active && <Button size="sm" variant="ghost" title={t('extendHint')} onClick={() => void client.extendSession(create(ExtendSessionRequestSchema, { id: s.id })).then(onChanged)}>{t('extend')}</Button>}
        {s.active && <ConfirmAction trigger={<Button size="sm" variant="outline">{t('revoke')}</Button>} title={t('revokeTitle')} description={t('revokeDescription')}
        confirmLabel={t('revoke')} onConfirm={async (signal) => { await client.revokeSessions(create(RevokeSessionsRequestSchema, { sessionId: s.id }), { signal }); onChanged(); }} />}</TableCell>
    </TableRow>)}</TableBody></Table>;
}

function Sessions() {
  const t = useText(), client = useClient(AdminServiceClient);
  const [activeOnly, setActiveOnly] = useState(true), [pages, setPages] = useState<string[]>(['']);
  const page = pages[pages.length - 1] ?? '';
  const list = usePlatformQuery(`kratos:sessions:${activeOnly}:${page}`, (signal) => client.listSessions(create(ListSessionsRequestSchema, { activeOnly, pageToken: page, pageSize: 50 }), { signal }), { keep: true });
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('sessionsTitle')} description={t('sessionsDescription')} actions={<Stack direction="row" gap={8}>
      <Button size="sm" variant={activeOnly ? 'default' : 'outline'} onClick={() => { setActiveOnly(!activeOnly); setPages(['']); }}>{t('activeOnly')}</Button>
      <Button variant="outline" size="sm" onClick={list.refresh}>{t('refresh')}</Button></Stack>} />
    <Panel title={t('sessions')} count={list.value?.sessions.length} flush footer={<Stack direction="row" gap={8}>
      <Button size="sm" variant="outline" disabled={pages.length < 2} onClick={() => setPages(pages.slice(0, -1))}>{t('previous')}</Button>
      <Button size="sm" variant="outline" disabled={!list.value?.nextPageToken} onClick={() => list.value && setPages([...pages, list.value.nextPageToken])}>{t('next')}</Button></Stack>}>
      {list.error !== undefined ? <Failure error={list.error} /> : !list.value ? <Loading /> : <SessionTable sessions={list.value.sessions} onChanged={list.refresh} owner />}
    </Panel>
  </Stack>;
}

// ——— courier ———

const statuses = ['', 'queued', 'processing', 'sent', 'abandoned'] as const;

function Courier() {
  const t = useText(), client = useClient(AdminServiceClient);
  const [status, setStatus] = useState(''), [recipient, setRecipient] = useState(''), [applied, setApplied] = useState(''), [pages, setPages] = useState<string[]>(['']), [open, setOpen] = useState<Message>();
  const page = pages[pages.length - 1] ?? '';
  useEffect(() => { const id = setTimeout(() => { setApplied(recipient.trim()); setPages(['']); }, 300); return () => clearTimeout(id); }, [recipient]);
  const list = usePlatformQuery(`kratos:messages:${status}:${applied}:${page}`, (signal) => client.listMessages(create(ListMessagesRequestSchema, { status, recipient: applied, pageToken: page, pageSize: 50 }), { signal }), { keep: true });
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('courierTitle')} description={t('courierDescription')} actions={<Button variant="outline" size="sm" onClick={list.refresh}>{t('refresh')}</Button>} />
    <Stack direction="row" gap={8}>
      <NativeSelect aria-label={t('status')} value={status} onChange={(e) => { setStatus(e.target.value); setPages(['']); }}>
        {statuses.map((s) => <option key={s} value={s}>{s ? t(`status_${s}`) : t('anyStatus')}</option>)}
      </NativeSelect>
      <SearchInput value={recipient} onValueChange={setRecipient} label={t('recipient')} placeholder={t('recipient')} />
    </Stack>
    <Panel title={t('messages')} count={list.value?.messages.length} flush footer={<Stack direction="row" gap={8}>
      <Button size="sm" variant="outline" disabled={pages.length < 2} onClick={() => setPages(pages.slice(0, -1))}>{t('previous')}</Button>
      <Button size="sm" variant="outline" disabled={!list.value?.nextPageToken} onClick={() => list.value && setPages([...pages, list.value.nextPageToken])}>{t('next')}</Button></Stack>}>
      {list.error !== undefined ? <Failure error={list.error} /> : !list.value ? <Loading /> : !list.value.messages.length ? <EmptyState title={t('noMessages')} />
        : <Table><TableHeader><TableRow><TableHead>{t('recipient')}</TableHead><TableHead>{t('template')}</TableHead><TableHead>{t('status')}</TableHead><TableHead>{t('attempts')}</TableHead><TableHead>{t('created')}</TableHead></TableRow></TableHeader>
          <TableBody>{list.value.messages.map((m) => <TableRow key={m.id} style={{ cursor: 'pointer' }} onClick={() => setOpen(m)}>
            <TableCell style={mono}>{m.recipient}</TableCell><TableCell><Badge variant="outline">{m.channel}</Badge> <span style={mono}>{m.templateType}</span></TableCell>
            <TableCell><MessageStatus status={m.status} /></TableCell><TableCell>{m.sendCount}</TableCell><TableCell><Timestamp value={date(m.createdAt)} /></TableCell>
          </TableRow>)}</TableBody></Table>}
    </Panel>
    {open && <MessageCard message={open} onClose={() => setOpen(undefined)} />}
  </Stack>;
}

function MessageStatus({ status }: { status: string }) {
  const t = useText();
  const tone = status === 'sent' ? 'success' : status === 'abandoned' ? 'danger' : status === 'processing' ? 'info' : 'warning';
  return <StatusBadge tone={tone}>{t(`status_${status}`, { defaultValue: status })}</StatusBadge>;
}

function MessageCard({ message, onClose }: { message: Message; onClose: () => void }) {
  const t = useText(), client = useClient(AdminServiceClient), reveal = usePlatformAction<{ subject: string; body: string }>();
  const full = usePlatformQuery(`kratos:message:${message.id}`, (signal) => client.getMessage(create(GetMessageRequestSchema, { id: message.id }), { signal }));
  const m = full.value?.message ?? message;
  return <DetailDrawer open onOpenChange={(o) => !o && onClose()} size="lg" title={m.templateType} description={<span style={mono}>{m.recipient}</span>}>
    <Stack gap={16}>
      <KeyValueList items={[
        { label: t('status'), value: <MessageStatus status={m.status} /> }, { label: t('channel'), value: m.channel },
        { label: t('attempts'), value: String(m.sendCount) }, { label: t('created'), value: <Timestamp value={date(m.createdAt)} absolute /> },
      ]} />
      <Panel title={t('dispatches')} flush>
        {!m.dispatches.length ? <EmptyState title={t('noDispatches')} /> : <Table><TableBody>{m.dispatches.map((d, i) => <TableRow key={i}>
          <TableCell><Timestamp value={date(d.createdAt)} absolute /></TableCell><TableCell>{d.status === 'success' ? <StatusBadge tone="success">{d.status}</StatusBadge> : <StatusBadge tone="danger">{d.status}</StatusBadge>}</TableCell>
          <TableCell style={{ ...muted, ...mono, wordBreak: 'break-all' }}>{d.error}</TableCell></TableRow>)}</TableBody></Table>}
      </Panel>
      <Panel title={t('content')} description={t('contentHint')}>
        {reveal.value ? <Stack gap={8}><strong>{reveal.value.subject}</strong><pre style={{ ...mono, whiteSpace: 'pre-wrap', margin: 0, fontSize: 12 }}>{reveal.value.body}</pre></Stack>
          : <Stack direction="row" gap={8} style={{ alignItems: 'center' }}><Button size="sm" variant="outline" disabled={reveal.pending} onClick={() => void reveal.run(async (signal) => {
            const res = await client.getMessage(create(GetMessageRequestSchema, { id: message.id, reveal: true }), { signal }); return { subject: res.subject, body: res.body };
          })}>{t('reveal')}</Button><ActionError error={reveal.error} /></Stack>}
      </Panel>
    </Stack>
  </DetailDrawer>;
}

const importScaffold = JSON.stringify([
  { schema_id: 'default', traits: { email: 'ada@example.com' }, verifiable_addresses: [{ value: 'ada@example.com', via: 'email', verified: true, status: 'completed' }],
    credentials: { password: { config: { hashed_password: '$2a$10$…' } } } },
], null, 2);

/** Creates identities in one batch: imports and migrations. */
function Import() {
  const t = useText(), client = useClient(AdminServiceClient), { mode } = usePluginContext();
  const [json, setJson] = useState(importScaffold), run = usePlatformAction<ImportResult[]>();
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('importTitle')} description={t('importDescription')} />
    <Panel title={t('identities')} actions={<Stack direction="row" gap={8} style={{ alignItems: 'center' }}><ActionError error={run.error} />
      <Button size="sm" disabled={run.pending} onClick={() => void run.run(async (signal) => (await client.importIdentities(create(ImportIdentitiesRequestSchema, { identitiesJson: json }), { signal })).results)}>{run.pending ? t('importing') : t('import')}</Button></Stack>}>
      <CodeEditor label={t('identities')} value={json} onChange={setJson} language="json" mode={mode} height={360}
        validate={async (text) => { try { const v = JSON.parse(text); return Array.isArray(v) ? [] : [{ from: 0, to: text.length, severity: 'error', message: t('importArray') }]; } catch (e) { return [{ from: 0, to: text.length, severity: 'error', message: e instanceof Error ? e.message : String(e) }]; } }} />
    </Panel>
    {run.value && <Panel title={t('results')} count={run.value.length} flush>
      <Table><TableBody>{run.value.map((r, i) => <TableRow key={i}><TableCell>{i + 1}</TableCell>
        <TableCell>{r.action === 'create' ? <StatusBadge tone="success">{t('created')}</StatusBadge> : <StatusBadge tone="danger">{r.action}</StatusBadge>}</TableCell>
        <TableCell style={mono}>{r.identityId}</TableCell><TableCell style={{ ...muted, color: r.error ? 'var(--destructive)' : undefined }}>{r.error}</TableCell></TableRow>)}</TableBody></Table>
    </Panel>}
  </Stack>;
}

function Schemas() {
  const t = useText(), schemas = useSchemas(), { mode } = usePluginContext();
  return <Stack gap={16}><ConnectionNotice />
    <Header title={t('schemasTitle')} description={t('schemasDescription')} actions={<Button variant="outline" size="sm" onClick={schemas.refresh}>{t('refresh')}</Button>} />
    {schemas.error !== undefined ? <Failure error={schemas.error} /> : !schemas.value ? <Loading /> : !schemas.value.schemas.length ? <EmptyState title={t('noSchemas')} />
      : schemas.value.schemas.map((s) => <Panel key={s.id} title={s.id}>
        <CodeEditor label={s.id} value={JSON.stringify(JSON.parse(s.schemaJson || '{}'), null, 2)} language="json" mode={mode} readOnly height={280} />
      </Panel>)}
  </Stack>;
}

function Missing() {
  const t = useText(), navigate = usePluginNavigate();
  return <Panel><EmptyState title={<h1 style={{ margin: 0, fontSize: 16, fontWeight: 500 }}>{t('missing')}</h1>} action={<Button size="sm" variant="outline" onClick={() => navigate('')}>{t('back')}</Button>} /></Panel>;
}

export const definition = definePlugin({
  ...navigation,
  routes: [
    { index: true, element: <Overview /> }, { path: 'flows', element: <Flows /> }, { path: 'identities', element: <Identities /> }, { path: 'sessions', element: <Sessions /> },
    { path: 'import', element: <Import /> }, { path: 'courier', element: <Courier /> }, { path: 'schemas', element: <Schemas /> }, { path: 'settings', element: <Settings /> }, { path: '*', element: <Missing /> },
  ],
});

export type { Identity };
