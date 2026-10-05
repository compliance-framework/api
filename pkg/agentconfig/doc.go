// Package agentconfig is the configuration model shared by the CCF agent and the API for
// remote agent configuration: the declared config types, RFC 7396 merge of an API-stored
// overlay onto the agent's file config, overlay validation, change-safety classification,
// redaction, digests, opaque ETags, and the agent<->API wire types.
//
// The package does no I/O and never imports OPA, so importing agentconfig (as sdk/ does)
// stays light.
//
// Conventions:
//   - Config documents are snake_case JSON and are treated as opaque by API envelopes.
//   - Every path that addresses a config document is an RFC 6901 JSON Pointer (see Pointer).
//   - Overlay null semantics follow RFC 7396: omitting a key keeps the file's value, while
//     null deletes the key from the effective config so the agent's default applies.
//   - Only ValidateOverlay decodes strictly. Merge, Validate, ValidateEditable, Classify,
//     Redact and Digest never reject unknown fields or weakly-typed values in a base.
package agentconfig
