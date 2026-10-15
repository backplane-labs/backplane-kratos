import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { usePluginContext } from '@backplane-labs/backplane-plugin-sdk';
import { ConnectionNotice } from '@backplane-labs/backplane-platform-ui';
import { CodeEditor } from '@backplane-labs/backplane-editors';
import { Badge, Button, EmptyState, Input, NativeSelect, PageHeader, Panel, SecretInput, Skeleton, Stack, StatusBadge } from '@backplane-labs/backplane-ui';
import { Choice, Duration, Lines, NumberField, Row, SaveBar, Text, Toggle, useLiveConfig, type Json, type LiveConfig } from './settings-kit';

const S = 'settings';
const durationFields = ['registration.lifespan', 'login.lifespan', 'settings.lifespan', 'settings.privileged_session_max_age', 'recovery.lifespan',
  'verification.lifespan', 'methods.code.lifespan', 'session.lifespan', 'session.earliest_possible_extend'] as const;
const muted = { color: 'var(--muted-foreground)', fontSize: 12 } as const;
const providers = ['generic', 'google', 'github', 'gitlab', 'microsoft', 'apple', 'discord', 'slack', 'facebook', 'auth0', 'yandex', 'vk'] as const;

function useText() { return useTranslation('module.kratos').t; }

type Provider = { id?: string; provider?: string; label?: string; client_id?: string; issuer_url?: string; scope?: string[]; mapper?: string; extra?: Record<string, string> };

const mapperScaffold = `local claims = std.extVar('claims');
{
  identity: {
    traits: {
      email: claims.email,
    },
  },
}`;

/** Kratos's settings: written to the overlay Kratos reloads, as a revision of this service's configuration. */
export function Settings() {
  const t = useText(), cfg = useLiveConfig('kratos', { settings: durationFields });
  const labels = {
    comment: t('changeComment'), validate: t('validate'), save: t('saveRevision'), saving: t('saving'), reset: t('reset'),
    valid: t('valid'), saved: t('savedRevision'), unsaved: t('unsaved'), revision: t('revision'),
  };
  return <Stack gap={16}><ConnectionNotice />
    <PageHeader title={t('settingsTitle')} description={t('settingsDescription')} />
    {cfg.error !== undefined ? <EmptyState role="alert" title={t('error')} /> : cfg.loading
      ? <Stack gap={8} role="status" aria-label={t('loading')}><Skeleton style={{ height: 120 }} /><Skeleton style={{ height: 120 }} /></Stack>
      : <>
        <SaveBar cfg={cfg} labels={labels} />
        <General cfg={cfg} />
        <Methods cfg={cfg} />
        <Oidc cfg={cfg} />
        <Sessions cfg={cfg} />
        <Features cfg={cfg} />
        <Schemas cfg={cfg} />
        <Hydra cfg={cfg} />
        <Overrides cfg={cfg} />
        <SaveBar cfg={cfg} labels={labels} />
      </>}
  </Stack>;
}

function General({ cfg }: { cfg: LiveConfig }) {
  const t = useText();
  return <Panel title={t('generalSection')} description={t('generalHint')}>
    <Text cfg={cfg} path={S} field="default_return_url" label={t('defaultReturnUrl')} placeholder="https://app.example.com/" />
    <Lines cfg={cfg} path={S} field="allowed_return_urls" label={t('allowedReturnUrls')} hint={t('onePerLine')} />
    <Text cfg={cfg} path={S} field="error_ui_url" label={t('errorUi')} />
  </Panel>;
}

function Methods({ cfg }: { cfg: LiveConfig }) {
  const t = useText(), m = 'methods.';
  const on = (method: string) => cfg.get(S, `${m}${method}.enabled`) === true;
  return <Panel title={t('methodsSection')} description={t('methodsHint')}>
    <Toggle cfg={cfg} path={S} field={`${m}password.enabled`} label={t('password')} />
    {on('password') && <>
      <NumberField cfg={cfg} path={S} field={`${m}password.min_length`} label={t('minLength')} min={6} />
      <Toggle cfg={cfg} path={S} field={`${m}password.identifier_similarity_check`} label={t('similarity')} />
      <Toggle cfg={cfg} path={S} field={`${m}password.haveibeenpwned`} label={t('pwned')} />
    </>}
    <Toggle cfg={cfg} path={S} field={`${m}code.enabled`} label={t('codes')} hint={t('codesHint')} />
    {on('code') && <>
      <Toggle cfg={cfg} path={S} field={`${m}code.passwordless`} label={t('codePasswordless')} />
      <Toggle cfg={cfg} path={S} field={`${m}code.mfa`} label={t('codeMfa')} />
      <Duration cfg={cfg} path={S} field={`${m}code.lifespan`} label={t('codeLifespan')} />
    </>}
    <Toggle cfg={cfg} path={S} field={`${m}totp.enabled`} label={t('totp')} />
    {on('totp') && <Text cfg={cfg} path={S} field={`${m}totp.issuer`} label={t('totpIssuer')} />}
    <Toggle cfg={cfg} path={S} field={`${m}lookup_secret.enabled`} label={t('lookupSecret')} />
    <Toggle cfg={cfg} path={S} field={`${m}passkey.enabled`} label={t('passkey')} />
    {on('passkey') && <>
      <Text cfg={cfg} path={S} field={`${m}passkey.rp.id`} label={t('rpId')} placeholder="example.com" />
      <Text cfg={cfg} path={S} field={`${m}passkey.rp.display_name`} label={t('rpName')} />
      <Lines cfg={cfg} path={S} field={`${m}passkey.rp.origins`} label={t('rpOrigins')} hint={t('onePerLine')} />
    </>}
    <Toggle cfg={cfg} path={S} field={`${m}webauthn.enabled`} label={t('webauthn')} />
    {on('webauthn') && <>
      <Toggle cfg={cfg} path={S} field={`${m}webauthn.passwordless`} label={t('webauthnPasswordless')} />
      <Text cfg={cfg} path={S} field={`${m}webauthn.rp.id`} label={t('rpId')} />
      <Text cfg={cfg} path={S} field={`${m}webauthn.rp.display_name`} label={t('rpName')} />
      <Lines cfg={cfg} path={S} field={`${m}webauthn.rp.origins`} label={t('rpOrigins')} hint={t('onePerLine')} />
    </>}
    <Toggle cfg={cfg} path={S} field={`${m}profile.enabled`} label={t('profile')} />
    <Toggle cfg={cfg} path={S} field={`${m}link.enabled`} label={t('linkMethod')} hint={t('linkHint')} />
  </Panel>;
}

function Oidc({ cfg }: { cfg: LiveConfig }) {
  const t = useText(), { mode } = usePluginContext();
  const list = (cfg.get(S, 'methods.oidc.providers') as Provider[] | undefined) ?? [];
  const secrets = (cfg.get('oidc_secrets') as Record<string, string> | undefined) ?? {};
  const [entered, setEntered] = useState<Record<string, string>>({});
  const update = (i: number, p: Provider) => cfg.set(S, 'methods.oidc.providers', list.map((x, j) => (j === i ? p : x)) as unknown as Json);
  const ids = list.map((p) => p.id ?? '').filter(Boolean);
  const complete = ids.every((id) => entered[id]);
  return <Panel title={t('oidcSection')} description={t('oidcHint')}>
    <Toggle cfg={cfg} path={S} field="methods.oidc.enabled" label={t('oidcEnabled')} />
    {list.map((p, i) => <Panel key={i} title={p.label || p.id || t('newProvider')} actions={<Button size="sm" variant="ghost"
      onClick={() => cfg.set(S, 'methods.oidc.providers', list.filter((_, j) => j !== i) as unknown as Json)}>{t('remove')}</Button>}>
      <Row label={t('providerId')} hint={t('providerIdHint')}><Input aria-label={t('providerId')} value={p.id ?? ''} onChange={(e) => update(i, { ...p, id: e.target.value })} /></Row>
      <Row label={t('providerKind')}><NativeSelect aria-label={t('providerKind')} value={p.provider ?? 'generic'} onChange={(e) => update(i, { ...p, provider: e.target.value })}>
        {providers.map((k) => <option key={k} value={k}>{k}</option>)}</NativeSelect></Row>
      <Row label={t('providerLabel')}><Input aria-label={t('providerLabel')} value={p.label ?? ''} onChange={(e) => update(i, { ...p, label: e.target.value })} /></Row>
      <Row label={t('clientId')}><Input aria-label={t('clientId')} value={p.client_id ?? ''} onChange={(e) => update(i, { ...p, client_id: e.target.value })} /></Row>
      <Row label={t('issuerUrl')} hint={t('issuerUrlHint')}><Input aria-label={t('issuerUrl')} value={p.issuer_url ?? ''} onChange={(e) => update(i, { ...p, issuer_url: e.target.value })} /></Row>
      <Row label={t('scope')} hint={t('scopeHint')}><Input aria-label={t('scope')} value={(p.scope ?? []).join(' ')} onChange={(e) => update(i, { ...p, scope: e.target.value.split(/\s+/).filter(Boolean) })} /></Row>
      <Row label={t('secret')}>{p.id && secrets[p.id] ? <StatusBadge tone="success">{t('secretSet')}</StatusBadge> : <Badge variant="outline">{t('secretMissing')}</Badge>}</Row>
      <Row label={t('mapper')} hint={t('mapperHint')}><CodeEditor label={t('mapper')} value={p.mapper || mapperScaffold} onChange={(v) => update(i, { ...p, mapper: v })} language="text" mode={mode} height={160} /></Row>
    </Panel>)}
    <Stack direction="row" gap={8} style={{ marginTop: 8 }}>
      <Button size="sm" variant="outline" onClick={() => cfg.set(S, 'methods.oidc.providers', [...list, { provider: 'generic', scope: ['openid', 'email'], mapper: mapperScaffold }] as unknown as Json)}>{t('addProvider')}</Button>
    </Stack>
    {ids.length > 0 && <Panel title={t('providerSecrets')} description={t('providerSecretsHint')}>
      {ids.map((id) => <Row key={id} label={id}><SecretInput label={id} value={entered[id] ?? ''} onValueChange={(v) => setEntered({ ...entered, [id]: v })} /></Row>)}
      <Row label=""><Button size="sm" variant="outline" disabled={!complete} onClick={() => cfg.set('oidc_secrets', undefined, Object.fromEntries(ids.map((id) => [id, entered[id]!])))}>{t('stageSecrets')}</Button>
        {!complete && <span style={{ ...muted, marginLeft: 8 }}>{t('enterAllSecrets')}</span>}</Row>
    </Panel>}
  </Panel>;
}

function Features({ cfg }: { cfg: LiveConfig }) {
  const t = useText();
  return <Panel title={t('featuresSection')}>
    <Toggle cfg={cfg} path={S} field="features.continue_with" label={t('continueWith')} hint={t('continueWithHint')} />
    <Toggle cfg={cfg} path={S} field="features.choose_recovery_address" label={t('chooseRecovery')} hint={t('chooseRecoveryHint')} />
  </Panel>;
}

function Sessions({ cfg }: { cfg: LiveConfig }) {
  const t = useText();
  return <Panel title={t('sessionsSection')}>
    <Duration cfg={cfg} path={S} field="session.lifespan" label={t('lifespan')} />
    <Duration cfg={cfg} path={S} field="session.earliest_possible_extend" label={t('earliestExtend')} hint={t('earliestExtendHint')} />
    <Choice cfg={cfg} path={S} field="session.whoami_required_aal" label={t('whoamiAal')} options={['highest_available', 'aal1']} />
    <Text cfg={cfg} path={S} field="session.cookie_domain" label={t('cookieDomain')} placeholder="example.com" />
    <Toggle cfg={cfg} path={S} field="session.cookie_persistent" label={t('cookiePersistent')} />
    <Choice cfg={cfg} path={S} field="session.cookie_same_site" label={t('cookieSameSite')} options={['Lax', 'Strict', 'None']} />
  </Panel>;
}

const schemaScaffold = JSON.stringify({
  $schema: 'http://json-schema.org/draft-07/schema#', title: 'Person', type: 'object',
  properties: { traits: { type: 'object', properties: { email: { type: 'string', format: 'email', title: 'E-mail',
    'ory.sh/kratos': { credentials: { password: { identifier: true }, code: { identifier: true, via: 'email' } }, verification: { via: 'email' }, recovery: { via: 'email' } } } },
  required: ['email'], additionalProperties: false } },
}, null, 2);

function Schemas({ cfg }: { cfg: LiveConfig }) {
  const t = useText(), { mode } = usePluginContext();
  const schemas = (cfg.get(S, 'identity.schemas') as Record<string, string> | undefined) ?? {};
  const [name, setName] = useState('');
  const ids = Object.keys(schemas).sort();
  const put = (next: Record<string, string>) => cfg.set(S, 'identity.schemas', Object.keys(next).length ? next : undefined);
  return <Panel title={t('schemasSection')} description={t('schemasHint')}>
    {ids.length > 0 && <Choice cfg={cfg} path={S} field="identity.default_schema_id" label={t('defaultSchema')} options={ids} />}
    {ids.map((id) => <Panel key={id} title={id} actions={<Button size="sm" variant="ghost" onClick={() => { const n = { ...schemas }; delete n[id]; put(n); }}>{t('remove')}</Button>}>
      <CodeEditor label={id} value={schemas[id] ?? ''} onChange={(v) => put({ ...schemas, [id]: v })} language="json" mode={mode} height={260}
        validate={async (text) => { try { JSON.parse(text); return []; } catch (e) { return [{ from: 0, to: text.length, severity: 'error', message: e instanceof Error ? e.message : String(e) }]; } }} />
    </Panel>)}
    <Stack direction="row" gap={8} style={{ marginTop: 8 }}>
      <Input aria-label={t('schemaId')} placeholder={t('schemaId')} value={name} onChange={(e) => setName(e.target.value)} style={{ maxWidth: 240 }} />
      <Button size="sm" variant="outline" disabled={!name || name in schemas} onClick={() => { put({ ...schemas, [name]: schemaScaffold }); setName(''); }}>{t('addSchema')}</Button>
    </Stack>
    {!ids.length && <p style={muted}>{t('schemasFromBase')}</p>}
  </Panel>;
}

function Hydra({ cfg }: { cfg: LiveConfig }) {
  const t = useText();
  const headers = (cfg.get('oauth2_provider_headers') as Record<string, string> | undefined) ?? {};
  const [header, setHeader] = useState('Authorization'), [value, setValue] = useState('');
  return <Panel title={t('hydraSection')} description={t('hydraHint')}>
    <Text cfg={cfg} path={S} field="oauth2_provider.url" label={t('hydraAdminUrl')} placeholder="http://hydra-admin:4445" />
    <Toggle cfg={cfg} path={S} field="oauth2_provider.override_return_to" label={t('overrideReturnTo')} />
    <Row label={t('hydraHeaders')} hint={t('hydraHeadersHint')}><Stack gap={8}>
      <span style={muted}>{Object.keys(headers).length ? Object.keys(headers).join(', ') : t('none')}</span>
      <Stack direction="row" gap={8}><Input aria-label={t('headerName')} value={header} onChange={(e) => setHeader(e.target.value)} style={{ maxWidth: 180 }} />
        <SecretInput label={t('headerValue')} value={value} onValueChange={setValue} />
        <Button size="sm" variant="outline" disabled={!header || !value} onClick={() => cfg.set('oauth2_provider_headers', undefined, { [header]: value })}>{t('stageHeader')}</Button></Stack>
    </Stack></Row>
  </Panel>;
}


function Overrides({ cfg }: { cfg: LiveConfig }) {
  const t = useText(), { mode } = usePluginContext(), v = cfg.get(S, 'overrides');
  return <Panel title={t('overridesSection')} description={t('overridesHint')}>
    <CodeEditor label={t('overridesSection')} value={typeof v === 'string' ? v : ''} onChange={(text) => cfg.set(S, 'overrides', text || undefined)} language="yaml" mode={mode} height={180} />
  </Panel>;
}
