package risks

import (
	"time"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
)

const CCFPropsNamespace = "https://compliance-framework.io"

const (
	CCFPropLikelihood              = "ccf:likelihood"
	CCFPropImpact                  = "ccf:impact"
	CCFPropPrimaryOwnerUserID      = "ccf:primary-owner-user-id"
	CCFPropReviewDeadline          = "ccf:review-deadline"
	CCFPropAcceptanceJustification = "ccf:acceptance-justification"
)

// TODO[codex-5-3-high]: Implemented as requested in the risk-register plan, but currently dead code. Consider removing after full implementation is done.
func BuildCCFOscalProps(r Risk) []oscalTypes_1_1_3.Property {
	props := make([]oscalTypes_1_1_3.Property, 0)

	if r.Likelihood != nil && *r.Likelihood != "" {
		props = append(props, oscalTypes_1_1_3.Property{Name: CCFPropLikelihood, Ns: CCFPropsNamespace, Value: *r.Likelihood})
	}
	if r.Impact != nil && *r.Impact != "" {
		props = append(props, oscalTypes_1_1_3.Property{Name: CCFPropImpact, Ns: CCFPropsNamespace, Value: *r.Impact})
	}
	if r.PrimaryOwnerUserID != nil {
		props = append(props, oscalTypes_1_1_3.Property{Name: CCFPropPrimaryOwnerUserID, Ns: CCFPropsNamespace, Value: r.PrimaryOwnerUserID.String()})
	}
	if r.ReviewDeadline != nil {
		props = append(props, oscalTypes_1_1_3.Property{Name: CCFPropReviewDeadline, Ns: CCFPropsNamespace, Value: r.ReviewDeadline.UTC().Format(time.RFC3339)})
	}
	if r.AcceptanceJustification != nil {
		props = append(props, oscalTypes_1_1_3.Property{Name: CCFPropAcceptanceJustification, Ns: CCFPropsNamespace, Value: *r.AcceptanceJustification})
	}

	return props
}

// TODO[codex-5-3-high]: Implemented as requested in the risk-register plan, but currently dead code. Consider removing after full implementation is done.
func ApplyCCFPropsToRisk(props []oscalTypes_1_1_3.Property, r *Risk) {
	for _, prop := range props {
		if prop.Ns != CCFPropsNamespace {
			continue
		}

		switch prop.Name {
		case CCFPropLikelihood:
			v := prop.Value
			r.Likelihood = &v
		case CCFPropImpact:
			v := prop.Value
			r.Impact = &v
		case CCFPropPrimaryOwnerUserID:
			if parsed, err := uuid.Parse(prop.Value); err == nil {
				r.PrimaryOwnerUserID = &parsed
			}
		case CCFPropReviewDeadline:
			if parsed, err := time.Parse(time.RFC3339, prop.Value); err == nil {
				r.ReviewDeadline = &parsed
			}
		case CCFPropAcceptanceJustification:
			v := prop.Value
			r.AcceptanceJustification = &v
		}
	}
}

// TODO[codex-5-3-high]: Implemented as requested in the risk-register plan, but currently dead code. Consider removing after full implementation is done.
func (r *Risk) ToOSCAL() *oscalTypes_1_1_3.Risk {
	id := uuid.Nil.String()
	if r.ID != nil {
		id = r.ID.String()
	}

	statement := r.Description
	if statement == "" {
		statement = r.Title
	}

	ret := &oscalTypes_1_1_3.Risk{
		UUID:        id,
		Title:       r.Title,
		Description: r.Description,
		Statement:   statement,
		Status:      r.Status,
	}
	props := BuildCCFOscalProps(*r)
	if len(props) > 0 {
		ret.Props = &props
	}
	return ret
}

// TODO[codex-5-3-high]: Implemented as requested in the risk-register plan, but currently dead code. Consider removing after full implementation is done.
func (r *Risk) FromOSCAL(or oscalTypes_1_1_3.Risk) *Risk {
	if parsed, err := uuid.Parse(or.UUID); err == nil {
		r.ID = &parsed
	}

	r.Title = or.Title
	r.Description = or.Description
	if r.Description == "" {
		r.Description = or.Statement
	}
	r.Status = or.Status
	r.SourceType = string(RiskSourceTypeOscalImport)
	if or.Props != nil {
		ApplyCCFPropsToRisk(*or.Props, r)
	}
	return r
}
