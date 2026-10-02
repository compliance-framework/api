package evidence

// EvidenceOrigin is where a piece of evidence came from. It decides which subject rules
// apply to it.
type EvidenceOrigin string

const (
	OriginAgent    EvidenceOrigin = "agent"
	OriginUser     EvidenceOrigin = "user"
	OriginWorkflow EvidenceOrigin = "workflow"
	OriginSystem   EvidenceOrigin = "system"
)

// OriginFromSigner derives the origin of evidence submitted through the API: a user signer
// means user, and an agent signer or no signer (anonymous public ingest) means agent.
func OriginFromSigner(signer *SignerContext) EvidenceOrigin {
	if signer != nil && signer.User != nil {
		return OriginUser
	}
	return OriginAgent
}

// EffectiveOrigin is the origin the evidence is treated as: the one its creation path set
// explicitly (workflow and system paths do), otherwise the one its signer implies.
func (p CreateEvidenceParams) EffectiveOrigin() EvidenceOrigin {
	if p.Origin != "" {
		return p.Origin
	}
	return OriginFromSigner(p.Signer)
}
