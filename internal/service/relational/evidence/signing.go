package evidence

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/datatypes"
)

const evidenceSignatureVersion = "v1"

type SignerContext struct {
	User  *UserSignerContext
	Agent *AgentSignerContext
}

type UserSignerContext struct {
	Claims *authn.UserClaims
}

type AgentSignerContext struct {
	Claims *authn.AgentClaims
	Agent  *relational.Agent
	Key    *relational.AgentServiceAccountKey
}

func (s *SignerContext) IsEmpty() bool {
	return s == nil || (s.User == nil && s.Agent == nil)
}

func (s *SignerContext) SubmittedByValue() string {
	if s == nil {
		return ""
	}
	if s.User != nil && s.User.Claims != nil {
		return s.User.Claims.Subject
	}
	if s.Agent != nil {
		if s.Agent.Agent != nil && s.Agent.Agent.Name != "" {
			return s.Agent.Agent.Name
		}
		if s.Agent.Claims != nil {
			return s.Agent.Claims.Subject
		}
	}
	return ""
}

func (s *SignerContext) signerSnapshot() relational.EvidenceSignatureSigner {
	if s == nil {
		return relational.EvidenceSignatureSigner{}
	}
	if s.User != nil && s.User.Claims != nil {
		return relational.EvidenceSignatureSigner{
			Type:  authn.TokenKindUser,
			Email: s.User.Claims.Subject,
			Name:  strings.TrimSpace(strings.Join([]string{s.User.Claims.GivenName, s.User.Claims.FamilyName}, " ")),
		}
	}
	if s.Agent != nil {
		signer := relational.EvidenceSignatureSigner{
			Type: authn.TokenKindAgent,
		}
		if s.Agent.Agent != nil {
			signer.ID = s.Agent.Agent.ID.String()
			signer.Name = s.Agent.Agent.Name
		}
		if s.Agent.Key != nil {
			signer.CredentialID = s.Agent.Key.ID.String()
		}
		if s.Agent.Claims != nil {
			signer.ID = firstNonEmpty(signer.ID, s.Agent.Claims.AgentID)
		}
		return signer
	}
	return relational.EvidenceSignatureSigner{}
}

func (s *SignerContext) claimsSnapshot() relational.EvidenceSignatureClaims {
	if s == nil {
		return relational.EvidenceSignatureClaims{}
	}
	if s.User != nil && s.User.Claims != nil {
		claims := s.User.Claims
		return relational.EvidenceSignatureClaims{
			TokenKind:  firstNonEmpty(claims.TokenKind, authn.TokenKindUser),
			Subject:    claims.Subject,
			Issuer:     claims.Issuer,
			IssuedAt:   numericDateToTime(claims.IssuedAt),
			ExpiresAt:  numericDateToTime(claims.ExpiresAt),
			NotBefore:  numericDateToTime(claims.NotBefore),
			GivenName:  claims.GivenName,
			FamilyName: claims.FamilyName,
		}
	}
	if s.Agent != nil && s.Agent.Claims != nil {
		claims := s.Agent.Claims
		return relational.EvidenceSignatureClaims{
			TokenKind:    firstNonEmpty(claims.TokenKind, authn.TokenKindAgent),
			Subject:      claims.Subject,
			Issuer:       claims.Issuer,
			IssuedAt:     numericDateToTime(claims.IssuedAt),
			ExpiresAt:    numericDateToTime(claims.ExpiresAt),
			NotBefore:    numericDateToTime(claims.NotBefore),
			AgentID:      claims.AgentID,
			CredentialID: claims.CredentialID,
			AuthMethod:   claims.AuthMethod,
		}
	}
	return relational.EvidenceSignatureClaims{}
}

type SigningService struct {
	privateKey *rsa.PrivateKey
	now        func() time.Time
}

func NewSigningService(privateKey *rsa.PrivateKey) *SigningService {
	return &SigningService{
		privateKey: privateKey,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

func (s *SigningService) SignEvidence(params CreateEvidenceParams, signer *SignerContext) (*datatypes.JSONType[relational.EvidenceSignature], error) {
	if signer == nil || signer.IsEmpty() {
		return nil, nil
	}
	if s == nil || s.privateKey == nil {
		return nil, errors.New("evidence signing key is not configured")
	}

	contentHash, err := computeEvidenceContentHash(params)
	if err != nil {
		return nil, err
	}
	signature := relational.EvidenceSignature{
		Version:            evidenceSignatureVersion,
		SignatureAlgorithm: jwt.SigningMethodRS256.Alg(),
		SignedAt:           s.now().UTC(),
		ContentHash:        contentHash,
		Signer:             signer.signerSnapshot(),
		Claims:             signer.claimsSnapshot(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, buildSignatureTokenClaims(signature))
	jws, err := token.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign evidence payload: %w", err)
	}
	signature.JWS = jws

	data := datatypes.NewJSONType(signature)
	return &data, nil
}

func computeEvidenceContentHash(params CreateEvidenceParams) (relational.Hash, error) {
	canonical, err := canonicalizeEvidence(params)
	if err != nil {
		return relational.Hash{}, fmt.Errorf("canonicalize evidence: %w", err)
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return relational.Hash{}, fmt.Errorf("marshal canonical evidence: %w", err)
	}

	sum := sha256.Sum256(payload)
	return relational.Hash{
		Algorithm: relational.HashAlgorithmSHA_256,
		Value:     hex.EncodeToString(sum[:]),
	}, nil
}

func buildSignatureTokenClaims(signature relational.EvidenceSignature) jwt.MapClaims {
	return jwt.MapClaims{
		"token_kind":          authn.TokenKindEvidenceSignature,
		"version":             signature.Version,
		"signature_algorithm": signature.SignatureAlgorithm,
		"signed_at":           signature.SignedAt.Format(time.RFC3339Nano),
		"content_hash": map[string]any{
			"algorithm": signature.ContentHash.Algorithm,
			"value":     signature.ContentHash.Value,
		},
		"signer": signature.Signer,
		"claims": signature.Claims,
	}
}

type canonicalEvidence struct {
	UUID           string                               `json:"uuid,omitempty"`
	Title          string                               `json:"title,omitempty"`
	Description    string                               `json:"description,omitempty"`
	Remarks        *string                              `json:"remarks,omitempty"`
	Start          string                               `json:"start,omitempty"`
	End            string                               `json:"end,omitempty"`
	Expires        *string                              `json:"expires,omitempty"`
	Props          []oscalTypes_1_1_3.Property          `json:"props,omitempty"`
	Links          []oscalTypes_1_1_3.Link              `json:"links,omitempty"`
	Origins        []oscalTypes_1_1_3.Origin            `json:"origins,omitempty"`
	Activities     []oscalTypes_1_1_3.Activity          `json:"activities,omitempty"`
	InventoryItems []oscalTypes_1_1_3.InventoryItem     `json:"inventory_items,omitempty"`
	Components     []oscalTypes_1_1_3.SystemComponent   `json:"components,omitempty"`
	Subjects       []oscalTypes_1_1_3.AssessmentSubject `json:"subjects,omitempty"`
	Status         oscalTypes_1_1_3.ObjectiveStatus     `json:"status"`
	BackMatter     *oscalTypes_1_1_3.BackMatter         `json:"back_matter,omitempty"`
	Labels         []canonicalLabel                     `json:"labels,omitempty"`
}

type canonicalLabel struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func canonicalizeEvidence(params CreateEvidenceParams) (*canonicalEvidence, error) {
	evidence := params.Evidence

	activities := make([]oscalTypes_1_1_3.Activity, 0, len(params.Activities))
	for _, activity := range params.Activities {
		osc := activity.MarshalOscal()
		if osc == nil {
			continue
		}
		if osc.Steps != nil {
			sortedSteps := sortByJSONValue(*osc.Steps)
			osc.Steps = &sortedSteps
		}
		activities = append(activities, *osc)
	}

	inventoryItems := make([]oscalTypes_1_1_3.InventoryItem, 0, len(params.InventoryItems))
	for _, item := range params.InventoryItems {
		osc := item.MarshalOscal()
		if osc.ImplementedComponents != nil {
			sortedComponents := sortByJSONValue(*osc.ImplementedComponents)
			osc.ImplementedComponents = &sortedComponents
		}
		inventoryItems = append(inventoryItems, osc)
	}

	components := make([]oscalTypes_1_1_3.SystemComponent, 0, len(params.Components))
	for _, component := range params.Components {
		osc := component.MarshalOscal()
		if osc.Protocols != nil {
			protocols := *osc.Protocols
			for i := range protocols {
				if protocols[i].PortRanges != nil {
					sortedRanges := sortByJSONValue(*protocols[i].PortRanges)
					protocols[i].PortRanges = &sortedRanges
				}
			}
			protocols = sortByJSONValue(protocols)
			osc.Protocols = &protocols
		}
		components = append(components, *osc)
	}

	subjects := make([]oscalTypes_1_1_3.AssessmentSubject, 0, len(params.Subjects))
	for _, subject := range params.Subjects {
		osc := subject.MarshalOscal()
		if osc.IncludeSubjects != nil {
			sortedInclude := sortByJSONValue(*osc.IncludeSubjects)
			osc.IncludeSubjects = &sortedInclude
		}
		if osc.ExcludeSubjects != nil {
			sortedExclude := sortByJSONValue(*osc.ExcludeSubjects)
			osc.ExcludeSubjects = &sortedExclude
		}
		subjects = append(subjects, *osc)
	}

	origins := make([]oscalTypes_1_1_3.Origin, 0, len(evidence.Origins))
	for _, origin := range evidence.Origins {
		osc := oscalTypes_1_1_3.Origin(origin)
		osc.Actors = sortByJSONValue(osc.Actors)
		origins = append(origins, osc)
	}

	labels := make([]canonicalLabel, 0, len(params.Labels))
	for _, label := range params.Labels {
		labels = append(labels, canonicalLabel{Name: label.Name, Value: label.Value})
	}

	var backMatter *oscalTypes_1_1_3.BackMatter
	if evidence.BackMatter != nil {
		backMatter = evidence.BackMatter.MarshalOscal()
		if backMatter != nil && backMatter.Resources != nil {
			resources := *backMatter.Resources
			for i := range resources {
				if resources[i].Props != nil {
					sortedProps := sortByJSONValue(*resources[i].Props)
					resources[i].Props = &sortedProps
				}
				if resources[i].DocumentIds != nil {
					sortedDocs := sortByJSONValue(*resources[i].DocumentIds)
					resources[i].DocumentIds = &sortedDocs
				}
				if resources[i].Rlinks != nil {
					rlinks := *resources[i].Rlinks
					for j := range rlinks {
						if rlinks[j].Hashes != nil {
							sortedHashes := sortByJSONValue(*rlinks[j].Hashes)
							rlinks[j].Hashes = &sortedHashes
						}
					}
					rlinks = sortByJSONValue(rlinks)
					resources[i].Rlinks = &rlinks
				}
			}
			resources = sortByJSONValue(resources)
			backMatter.Resources = &resources
		}
	}

	status := evidence.Status.Data()
	canonical := &canonicalEvidence{
		UUID:           evidence.UUID.String(),
		Title:          evidence.Title,
		Description:    evidence.Description,
		Remarks:        evidence.Remarks,
		Start:          formatTime(evidence.Start),
		End:            formatTime(evidence.End),
		Expires:        formatTimePtr(evidence.Expires),
		Props:          sortByJSONValue(derefSlice(relational.ConvertPropsToOscal(evidence.Props))),
		Links:          sortByJSONValue(derefSlice(relational.ConvertLinksToOscal(evidence.Links))),
		Origins:        sortByJSONValue(origins),
		Activities:     sortByJSONValue(activities),
		InventoryItems: sortByJSONValue(inventoryItems),
		Components:     sortByJSONValue(components),
		Subjects:       sortByJSONValue(subjects),
		Status:         normalizeObjectiveStatus(status),
		BackMatter:     backMatter,
		Labels:         sortByJSONValue(labels),
	}
	return canonical, nil
}

func normalizeObjectiveStatus(status oscalTypes_1_1_3.ObjectiveStatus) oscalTypes_1_1_3.ObjectiveStatus {
	return oscalTypes_1_1_3.ObjectiveStatus{
		State:   status.State,
		Reason:  status.Reason,
		Remarks: status.Remarks,
	}
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	formatted := formatTime(*t)
	return &formatted
}

func numericDateToTime(date *jwt.NumericDate) *time.Time {
	if date == nil {
		return nil
	}
	utc := date.UTC()
	return &utc
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func derefSlice[T any](items *[]T) []T {
	if items == nil {
		return nil
	}
	return append([]T(nil), (*items)...)
}

func sortByJSONValue[T any](items []T) []T {
	if len(items) == 0 {
		return nil
	}
	sorted := append([]T(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return canonicalJSONString(sorted[i]) < canonicalJSONString(sorted[j])
	})
	return sorted
}

func canonicalJSONString(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%T:%v", value, value)
	}
	return string(data)
}

func NewUserSignerContextFromClaims(claims *authn.UserClaims) *SignerContext {
	if claims == nil {
		return nil
	}
	return &SignerContext{
		User: &UserSignerContext{
			Claims: claims,
		},
	}
}

func NewAgentSignerContext(claims *authn.AgentClaims, agent *relational.Agent, key *relational.AgentServiceAccountKey) *SignerContext {
	if claims == nil && agent == nil && key == nil {
		return nil
	}
	return &SignerContext{
		Agent: &AgentSignerContext{
			Claims: claims,
			Agent:  agent,
			Key:    key,
		},
	}
}
