package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	SignatureStatusSigned   = "signed"
	SignatureStatusUnsigned = "unsigned"
)

type SignatureDetail struct {
	Status    string                        `json:"status"`
	Signature *relational.EvidenceSignature `json:"signature,omitempty"`
}

type VerificationChecks struct {
	HashMatch            bool `json:"hash_match"`
	SignatureValid       bool `json:"signature_valid"`
	TemporalValid        bool `json:"temporal_valid"`
	SignedContentMatches bool `json:"signed_content_matches"`
}

type VerificationResult struct {
	Status      string                              `json:"status"`
	Signature   *relational.EvidenceSignature       `json:"signature,omitempty"`
	IsValid     bool                                `json:"is_valid"`
	Checks      VerificationChecks                  `json:"checks"`
	Errors      []string                            `json:"errors,omitempty"`
	ContentHash *relational.Hash                    `json:"content_hash,omitempty"`
	Signer      *relational.EvidenceSignatureSigner `json:"signer,omitempty"`
	Claims      *relational.EvidenceSignatureClaims `json:"claims,omitempty"`
	SignedAt    *time.Time                          `json:"signed_at,omitempty"`
}

func (s *EvidenceService) GetSignatureByID(id uuid.UUID) (*SignatureDetail, error) {
	evidence, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}
	signature := signatureFromEvidence(evidence)
	if signature != nil {
		return &SignatureDetail{
			Status:    SignatureStatusSigned,
			Signature: signature,
		}, nil
	}
	return &SignatureDetail{
		Status: SignatureStatusUnsigned,
	}, nil
}

func (s *EvidenceService) VerifyByID(id uuid.UUID) (*VerificationResult, error) {
	evidence, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}
	return s.verifyEvidence(evidence)
}

func (s *EvidenceService) verifyEvidence(evidence *relational.Evidence) (*VerificationResult, error) {
	signature := signatureFromEvidence(evidence)
	result := &VerificationResult{}
	if signature == nil {
		result.Status = SignatureStatusUnsigned
		return result, nil
	}

	result.Status = SignatureStatusSigned
	result.Signature = signature
	result.ContentHash = &signature.ContentHash
	result.Signer = &signature.Signer
	result.Claims = &signature.Claims
	result.SignedAt = &signature.SignedAt

	currentHash, err := computeEvidenceContentHash(createEvidenceParamsFromModel(evidence))
	if err != nil {
		return nil, err
	}
	result.Checks.HashMatch = hashesEqual(signature.ContentHash, currentHash)
	if !result.Checks.HashMatch {
		result.Errors = append(result.Errors, "current evidence content does not match the stored signature envelope hash")
	}

	signedPayload, err := s.parseSignedPayload(signature.JWS)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("stored JWS signature is invalid: %v", err))
		return finalizeVerificationResult(result), nil
	}

	result.Checks.SignatureValid = signaturePayloadMatchesEnvelope(*signature, *signedPayload)
	if !result.Checks.SignatureValid {
		result.Errors = append(result.Errors, "stored signature envelope does not match the signed payload")
	}

	result.Checks.SignedContentMatches = hashesEqual(signedPayload.ContentHash, currentHash)
	if !result.Checks.SignedContentMatches {
		result.Errors = append(result.Errors, "current evidence content does not match the hash contained in the signed payload")
	}

	result.Checks.TemporalValid, result.Errors = appendTemporalVerification(result.Errors, signedPayload.SignedAt, signedPayload.Claims)
	return finalizeVerificationResult(result), nil
}

func (s *EvidenceService) parseSignedPayload(jws string) (*relational.EvidenceSignature, error) {
	if s == nil || s.cfg == nil || s.cfg.JWTPublicKey == nil {
		return nil, errors.New("evidence verification key is not configured")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(jws, claims, func(token *jwt.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, jwt.ErrSignatureInvalid
		}
		return s.cfg.JWTPublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}
	if tokenKind, _ := claims["token_kind"].(string); tokenKind != authn.TokenKindEvidenceSignature {
		return nil, errors.New("unexpected token kind")
	}

	var payload relational.EvidenceSignature
	if err := decodeJSONValue(claims, &payload); err != nil {
		return nil, fmt.Errorf("decode signed payload: %w", err)
	}
	return &payload, nil
}

func createEvidenceParamsFromModel(evidence *relational.Evidence) CreateEvidenceParams {
	return CreateEvidenceParams{
		Evidence:       *evidence,
		Components:     append([]relational.SystemComponent(nil), evidence.Components...),
		InventoryItems: append([]relational.InventoryItem(nil), evidence.InventoryItems...),
		Activities:     append([]relational.Activity(nil), evidence.Activities...),
		Subjects:       append([]relational.AssessmentSubject(nil), evidence.Subjects...),
		Labels:         append([]relational.Labels(nil), evidence.Labels...),
	}
}

func signatureFromEvidence(evidence *relational.Evidence) *relational.EvidenceSignature {
	if evidence == nil || evidence.Signature == nil {
		return nil
	}
	signature := evidence.Signature.Data()
	return &signature
}

func signaturePayloadMatchesEnvelope(signature relational.EvidenceSignature, payload relational.EvidenceSignature) bool {
	signature.JWS = ""
	payload.JWS = ""
	return canonicalJSONString(buildSignatureTokenClaims(signature)) == canonicalJSONString(buildSignatureTokenClaims(payload))
}

func hashesEqual(left, right relational.Hash) bool {
	return left.Algorithm == right.Algorithm && left.Value == right.Value
}

func appendTemporalVerification(errorsList []string, signedAt time.Time, claims relational.EvidenceSignatureClaims) (bool, []string) {
	valid := true
	signedAt = signedAt.UTC()

	if claims.IssuedAt != nil && signedAt.Before(claims.IssuedAt.UTC()) {
		valid = false
		errorsList = append(errorsList, "signed_at is before the token issued_at time")
	}
	if claims.NotBefore != nil && signedAt.Before(claims.NotBefore.UTC()) {
		valid = false
		errorsList = append(errorsList, "signed_at is before the token not_before time")
	}
	if claims.ExpiresAt != nil && signedAt.After(claims.ExpiresAt.UTC()) {
		valid = false
		errorsList = append(errorsList, "signed_at is after the token expiration time")
	}

	return valid, errorsList
}

func finalizeVerificationResult(result *VerificationResult) *VerificationResult {
	result.IsValid = result.Checks.HashMatch &&
		result.Checks.SignatureValid &&
		result.Checks.TemporalValid &&
		result.Checks.SignedContentMatches
	if len(result.Errors) == 0 {
		result.Errors = nil
	}
	return result
}

func decodeJSONValue(input any, out any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
