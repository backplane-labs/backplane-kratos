// The claims backplane-kratos puts into a session's token, next to Kratos's
// own (iss, sub = the identity, sid = the session, iat, nbf, exp, jti): how
// the user signed in, the address they sign in with and the identity's
// public metadata, where roles live.
local session = std.extVar('session');
local identity = session.identity;
local traits = std.get(identity, 'traits', {});

{
  claims: {
    aal: std.get(session, 'authenticator_assurance_level', 'aal1'),
    amr: [m.method for m in std.get(session, 'authentication_methods', [])],
    authenticated_at: std.get(session, 'authenticated_at', null),
    schema_id: identity.schema_id,
    email: if std.isObject(traits) then std.get(traits, 'email', null) else null,
    metadata: std.get(identity, 'metadata_public', null),
  },
}
