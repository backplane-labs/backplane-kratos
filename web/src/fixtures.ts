import { create } from '@bufbuild/protobuf';
import { timestampNow } from '@bufbuild/protobuf/wkt';
import type { ClientRuntime, ClientConstructor, ClientState } from '@backplane-labs/backplane-client';
import {
  GetIdentityResponseSchema, GetMessageResponseSchema, GetOverlayResponseSchema, GetStatusResponseSchema, IdentitySchema, ListIdentitiesResponseSchema,
  ListMessagesResponseSchema, ListSchemasResponseSchema, ListSessionsResponseSchema, SessionSchema, type GetMessageRequest,
} from './gen/proto/kratos/console/v1/admin_pb';

const state: ClientState = { connection: 'connected', session: null, connectionId: 1 };
const schema = JSON.stringify({ type: 'object', properties: { traits: { type: 'object', properties: { email: { type: 'string', format: 'email' }, name: { type: 'string' } }, required: ['email'] } } });
const ada = create(IdentitySchema, {
  id: '5a1c7e2b-1a43-4bb0-9a47-0f0f2b4f1c11', schemaId: 'person', state: 'active', label: 'ada@example.com', traitsJson: '{"email":"ada@example.com","name":"Ada"}',
  metadataPublicJson: '{"tier":"gold"}', createdAt: timestampNow(), updatedAt: timestampNow(),
  verifiableAddresses: [{ value: 'ada@example.com', via: 'email', verified: true, status: 'completed' }],
  credentials: [{ type: 'password', identifiers: ['ada@example.com'] }, { type: 'totp', identifiers: ['5a1c7e2b'] }],
});
const session = create(SessionSchema, { id: '7c2e…', active: true, identityId: ada.id, identityLabel: ada.label, aal: 'aal2', methods: ['password', 'totp'], authenticatedAt: timestampNow(), expiresAt: timestampNow(), devices: [{ ipAddress: '203.0.113.7', userAgent: 'Firefox', location: 'Berlin, DE' }] });

/** Explicit local fixture of AdminService. */
export const fixtureClient: ClientRuntime = {
  getSnapshot: () => state, subscribe: () => () => {},
  client<T extends object>(constructor: ClientConstructor<T>): T {
    if (!('getStatus' in constructor.prototype)) throw new Error(`No fixture for ${constructor.name}`);
    return {
      async getStatus() { return create(GetStatusResponseSchema, {
        adminUrl: 'http://127.0.0.1:4434', publicUrl: 'http://127.0.0.1:4433', version: 'v26.2.0', events: true, callbacksUrl: 'http://127.0.0.1:8090',
        overlay: { path: '/etc/backplane/kratos.yml', hash: '3fa9c01e', writtenAt: timestampNow() },
        hooks: [{ name: 'Deliver', bound: true, description: 'Kratos\'s courier messages: codes and links by email or SMS' }, { name: 'AfterRegistration', bound: true, description: 'When a registration flow completes' }, { name: 'AfterLogin', bound: false, failOpen: true, description: 'When a login flow completes' }],
        callbacks: [{ point: 'courier/email', calls: 12n, lastOutcome: 'delivered', lastAt: timestampNow(), lastLatencyMs: 41.2 }, { point: 'hooks/after/registration', calls: 5n, failures: 1n, lastOutcome: 'denied', lastAt: timestampNow(), lastLatencyMs: 8.5 }],
      }); },
      async getOverlay() { return create(GetOverlayResponseSchema, { content: 'selfservice:\n  flows:\n    registration:\n      enabled: true\n' }); },
      async listIdentities() { return create(ListIdentitiesResponseSchema, { identities: [ada] }); },
      async getIdentity() { return create(GetIdentityResponseSchema, { identity: ada, sessions: [session] }); },
      async listSessions() { return create(ListSessionsResponseSchema, { sessions: [session] }); },
      async listSchemas() { return create(ListSchemasResponseSchema, { schemas: [{ id: 'person', schemaJson: schema }] }); },
      async listMessages() { return create(ListMessagesResponseSchema, { messages: [{ id: 'm1', status: 'sent', channel: 'email', recipient: 'ada@example.com', templateType: 'verification_code_valid', sendCount: 1, createdAt: timestampNow() }] }); },
      async getMessage(request: GetMessageRequest) { return create(GetMessageResponseSchema, { message: { id: request.id, status: 'sent', channel: 'email', recipient: 'ada@example.com', templateType: 'verification_code_valid', sendCount: 1, dispatches: [{ status: 'success', createdAt: timestampNow() }] }, ...(request.reveal ? { subject: 'Use code 123456', body: 'Your code is 123456' } : {}) }); },
    } as unknown as T;
  },
};
