package relational

import (
	"time"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// PlanOfActionAndMilestones represents a plan of action and milestones in OSCAL.
// It includes metadata, import-ssp, system-id, local-definitions, observations, risks, findings, poam-items, and back-matter.
type PlanOfActionAndMilestones struct {
	UUIDModel
	Metadata   Metadata   `json:"metadata" gorm:"polymorphic:Parent;"`
	BackMatter BackMatter `json:"back-matter" gorm:"polymorphic:Parent;"`

	// ImportSSP *ImportSSP `json:"import-ssp"`
	// SystemID  *SystemID  `json:"system-id"`
	// LocalDefinitions *LocalDefinitions `json:"local-definitions"`
	// Observations *Observations `json:"observations"`
	Risks     *[]Risk     `json:"risks"`
	PoamItems []PoamItem  `json:"poam-items"` // required in OSCAL
	// Findings *Findings `json:"findings"`
}

// UnmarshalOscal converts an OSCAL PlanOfActionAndMilestones into a relational PlanOfActionAndMilestones.
// It includes metadata, import-ssp, system-id, local-definitions, observations, risks, findings, poam-items, and back-matter.
func (p *PlanOfActionAndMilestones) UnmarshalOscal(opam oscalTypes_1_1_3.PlanOfActionAndMilestones) *PlanOfActionAndMilestones {
	metadata := &Metadata{}
	metadata.UnmarshalOscal(opam.Metadata)
	id := uuid.MustParse(opam.UUID)

	// ssps := ConvertList(opam.ImportSSPs, func(iss oscalTypes_1_1_3.ImportSSP) ImportSSP {
	// 	iss := ImportSSP{}
	// 	iss.UnmarshalOscal(iss)
	// 	return iss
	// })

	// systemIDs := ConvertList(opam.SystemIDs, func(is oscalTypes_1_1_3.SystemID) SystemID {
	// 	is := SystemID{}
	// 	is.UnmarshalOscal(is)
	// 	return is
	// })

	// localDefinitions := ConvertList(opam.LocalDefinitions, func(ld oscalTypes_1_1_3.LocalDefinition) LocalDefinition {
	// 	ld := LocalDefinition{}
	// 	ld.UnmarshalOscal(ld)
	// 	return ld
	// })

	// observations := ConvertList(opam.Observations, func(o oscalTypes_1_1_3.Observation) Observation {
	// 	o := Observation{}
	// 	o.UnmarshalOscal(o)
	// 	return o
	// })

	var risks *[]Risk
	if opam.Risks != nil {
		riskList := ConvertList(opam.Risks, func(or oscalTypes_1_1_3.Risk) Risk {
			r := Risk{}
			r.UnmarshalOscal(or)
			return r
		})
		risks = &riskList
	}

	// findings := ConvertList(opam.Findings, func(of oscalTypes_1_1_3.Finding) Finding {
	// 	f := Finding{}
	// 	f.UnmarshalOscal(of)
	// 	return f
	// })

	poamItems := ConvertList(&opam.PoamItems, func(opiam oscalTypes_1_1_3.PoamItem) PoamItem {
		poamItem := PoamItem{}
		poamItem.UnmarshalOscal(opiam)
		return poamItem
	})

	var backMatter BackMatter
	if opam.BackMatter != nil {
		backMatter.UnmarshalOscal(*opam.BackMatter)
	}

	*p = PlanOfActionAndMilestones{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Metadata:   *metadata,
		Risks:      risks,
		PoamItems:  poamItems,
		BackMatter: backMatter,
	}
	return p
}

// MarshalOscal converts the relational PlanOfActionAndMilestones back into an OSCAL PlanOfActionAndMilestones structure.
func (p *PlanOfActionAndMilestones) MarshalOscal() *oscalTypes_1_1_3.PlanOfActionAndMilestones {
	opam := oscalTypes_1_1_3.PlanOfActionAndMilestones{
		UUID: p.UUIDModel.ID.String(),
	}

	opam.Metadata = *p.Metadata.MarshalOscal()

	if p.Risks != nil {
		risks := make([]oscalTypes_1_1_3.Risk, len(*p.Risks))
		for i, r := range *p.Risks {
			risks[i] = *r.MarshalOscal()
		}
		opam.Risks = &risks
	}

	if len(p.PoamItems) > 0 {
		poamItems := make([]oscalTypes_1_1_3.PoamItem, len(p.PoamItems))
		for i, item := range p.PoamItems {
			poamItems[i] = *item.MarshalOscal()
		}
		opam.PoamItems = poamItems
	}

	if len(p.BackMatter.Resources) > 0 {
		bm := p.BackMatter.MarshalOscal()
		opam.BackMatter = bm
	}

	return &opam
}

// Risk represents a risk in OSCAL.
// It includes uuid, title, description, statement, props, links, status, origins, threat-ids, characterizations, mitigating-factors, deadline, remediations, risk-log, and related-observations.
type Risk struct {
	UUIDModel                                                         // required
	Title               string                                        `json:"title"`       // required
	Description         string                                        `json:"description"` // required
	Statement           string                                        `json:"statement"`   // required
	Status              string                                        `json:"status"`      // required
	Props               datatypes.JSONSlice[Prop]                     `json:"props"`
	Links               datatypes.JSONSlice[Link]                     `json:"links"`
	Origins             datatypes.JSONSlice[Origin]                   `json:"origins"`
	ThreatIds           datatypes.JSONSlice[ThreatId]                 `json:"threat-ids"`
	Characterizations   datatypes.JSONSlice[Characterization]         `json:"characterizations"`
	MitigatingFactors   datatypes.JSONSlice[MitigatingFactor]         `json:"mitigating-factors"`
	Deadline            *time.Time                                    `json:"deadline"`
	Remediations        datatypes.JSONSlice[Response]                 `json:"remediations"`
	RiskLog             *RiskLog                                      `json:"risk-log"`
	RelatedObservations datatypes.JSONSlice[RelatedObservation]       `json:"related-observations"`
}

// UnmarshalOscal converts an OSCAL Risk into a relational Risk.
func (r *Risk) UnmarshalOscal(or oscalTypes_1_1_3.Risk) *Risk {
	id := uuid.MustParse(or.UUID)
	
	props := ConvertOscalToProps(or.Props)
	links := ConvertOscalToLinks(or.Links)
	
	origins := ConvertList(or.Origins, func(oo oscalTypes_1_1_3.Origin) Origin {
		origin := Origin{}
		origin.UnmarshalOscal(oo)
		return origin
	})
	
	threatIds := ConvertList(or.ThreatIds, func(ot oscalTypes_1_1_3.ThreatId) ThreatId {
		threatId := ThreatId{}
		threatId.UnmarshalOscal(ot)
		return threatId
	})
	
	characterizations := ConvertList(or.Characterizations, func(oc oscalTypes_1_1_3.Characterization) Characterization {
		char := Characterization{}
		char.UnmarshalOscal(oc)
		return char
	})
	
	mitigatingFactors := ConvertList(or.MitigatingFactors, func(om oscalTypes_1_1_3.MitigatingFactor) MitigatingFactor {
		factor := MitigatingFactor{}
		factor.UnmarshalOscal(om)
		return factor
	})
	
	remediations := ConvertList(or.Remediations, func(or oscalTypes_1_1_3.Response) Response {
		response := Response{}
		response.UnmarshalOscal(or)
		return response
	})
	
	relatedObservations := ConvertList(or.RelatedObservations, func(oro oscalTypes_1_1_3.RelatedObservation) RelatedObservation {
		relObs := RelatedObservation{}
		relObs.UnmarshalOscal(oro)
		return relObs
	})
	
	var riskLog *RiskLog
	if or.RiskLog != nil {
		riskLog = &RiskLog{}
		riskLog.UnmarshalOscal(*or.RiskLog)
	}
	
	*r = Risk{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Title:               or.Title,
		Description:         or.Description,
		Statement:           or.Statement,
		Status:              or.Status,
		Props:               props,
		Links:               links,
		Origins:             datatypes.NewJSONSlice(origins),
		ThreatIds:           datatypes.NewJSONSlice(threatIds),
		Characterizations:   datatypes.NewJSONSlice(characterizations),
		MitigatingFactors:   datatypes.NewJSONSlice(mitigatingFactors),
		Deadline:            or.Deadline,
		Remediations:        datatypes.NewJSONSlice(remediations),
		RiskLog:             riskLog,
		RelatedObservations: datatypes.NewJSONSlice(relatedObservations),
	}
	return r
}

// MarshalOscal converts the relational Risk back into an OSCAL Risk structure.
func (r *Risk) MarshalOscal() *oscalTypes_1_1_3.Risk {
	ret := oscalTypes_1_1_3.Risk{
		UUID:        r.UUIDModel.ID.String(),
		Title:       r.Title,
		Description: r.Description,
		Statement:   r.Statement,
		Status:      r.Status,
	}
	
	if len(r.Props) > 0 {
		ret.Props = ConvertPropsToOscal(r.Props)
	}
	
	if len(r.Links) > 0 {
		ret.Links = ConvertLinksToOscal(r.Links)
	}
	
	if len(r.Origins) > 0 {
		origins := make([]oscalTypes_1_1_3.Origin, len(r.Origins))
		for i, origin := range r.Origins {
			origins[i] = *origin.MarshalOscal()
		}
		ret.Origins = &origins
	}
	
	if len(r.ThreatIds) > 0 {
		threatIds := make([]oscalTypes_1_1_3.ThreatId, len(r.ThreatIds))
		for i, threatId := range r.ThreatIds {
			threatIds[i] = *threatId.MarshalOscal()
		}
		ret.ThreatIds = &threatIds
	}
	
	if len(r.Characterizations) > 0 {
		characterizations := make([]oscalTypes_1_1_3.Characterization, len(r.Characterizations))
		for i, char := range r.Characterizations {
			characterizations[i] = *char.MarshalOscal()
		}
		ret.Characterizations = &characterizations
	}
	
	if len(r.MitigatingFactors) > 0 {
		factors := make([]oscalTypes_1_1_3.MitigatingFactor, len(r.MitigatingFactors))
		for i, factor := range r.MitigatingFactors {
			factors[i] = *factor.MarshalOscal()
		}
		ret.MitigatingFactors = &factors
	}
	
	if r.Deadline != nil {
		ret.Deadline = r.Deadline
	}
	
	if len(r.Remediations) > 0 {
		remediations := make([]oscalTypes_1_1_3.Response, len(r.Remediations))
		for i, response := range r.Remediations {
			remediations[i] = *response.MarshalOscal()
		}
		ret.Remediations = &remediations
	}
	
	if r.RiskLog != nil {
		ret.RiskLog = r.RiskLog.MarshalOscal()
	}
	
	if len(r.RelatedObservations) > 0 {
		relatedObservations := make([]oscalTypes_1_1_3.RelatedObservation, len(r.RelatedObservations))
		for i, relObs := range r.RelatedObservations {
			relatedObservations[i] = *relObs.MarshalOscal()
		}
		ret.RelatedObservations = &relatedObservations
	}
	
	return &ret
}

type Risks = []Risk

// Origin represents an origin in OSCAL.
type Origin oscalTypes_1_1_3.Origin

func (o *Origin) UnmarshalOscal(oo oscalTypes_1_1_3.Origin) *Origin {
	*o = Origin(oo)
	return o
}

func (o *Origin) MarshalOscal() *oscalTypes_1_1_3.Origin {
	origin := oscalTypes_1_1_3.Origin(*o)
	return &origin
}

// ThreatId represents a threat ID in OSCAL.
type ThreatId oscalTypes_1_1_3.ThreatId

func (t *ThreatId) UnmarshalOscal(ot oscalTypes_1_1_3.ThreatId) *ThreatId {
	*t = ThreatId(ot)
	return t
}

func (t *ThreatId) MarshalOscal() *oscalTypes_1_1_3.ThreatId {
	threatId := oscalTypes_1_1_3.ThreatId(*t)
	return &threatId
}

// Characterization represents a characterization in OSCAL.
type Characterization oscalTypes_1_1_3.Characterization

func (c *Characterization) UnmarshalOscal(oc oscalTypes_1_1_3.Characterization) *Characterization {
	*c = Characterization(oc)
	return c
}

func (c *Characterization) MarshalOscal() *oscalTypes_1_1_3.Characterization {
	char := oscalTypes_1_1_3.Characterization(*c)
	return &char
}

// MitigatingFactor represents a mitigating factor in OSCAL.
type MitigatingFactor oscalTypes_1_1_3.MitigatingFactor

func (m *MitigatingFactor) UnmarshalOscal(om oscalTypes_1_1_3.MitigatingFactor) *MitigatingFactor {
	*m = MitigatingFactor(om)
	return m
}

func (m *MitigatingFactor) MarshalOscal() *oscalTypes_1_1_3.MitigatingFactor {
	factor := oscalTypes_1_1_3.MitigatingFactor(*m)
	return &factor
}

// Response represents a response in OSCAL.
type Response oscalTypes_1_1_3.Response

func (r *Response) UnmarshalOscal(or oscalTypes_1_1_3.Response) *Response {
	*r = Response(or)
	return r
}

func (r *Response) MarshalOscal() *oscalTypes_1_1_3.Response {
	response := oscalTypes_1_1_3.Response(*r)
	return &response
}

// RiskLog represents a risk log in OSCAL.
type RiskLog oscalTypes_1_1_3.RiskLog

func (r *RiskLog) UnmarshalOscal(or oscalTypes_1_1_3.RiskLog) *RiskLog {
	*r = RiskLog(or)
	return r
}

func (r *RiskLog) MarshalOscal() *oscalTypes_1_1_3.RiskLog {
	riskLog := oscalTypes_1_1_3.RiskLog(*r)
	return &riskLog
}

// RelatedObservation represents a related observation in OSCAL.
type RelatedObservation oscalTypes_1_1_3.RelatedObservation

func (r *RelatedObservation) UnmarshalOscal(oro oscalTypes_1_1_3.RelatedObservation) *RelatedObservation {
	*r = RelatedObservation(oro)
	return r
}

func (r *RelatedObservation) MarshalOscal() *oscalTypes_1_1_3.RelatedObservation {
	relObs := oscalTypes_1_1_3.RelatedObservation(*r)
	return &relObs
}

// PoamItem represents a POAM item in OSCAL.
type PoamItem oscalTypes_1_1_3.PoamItem

func (p *PoamItem) UnmarshalOscal(op oscalTypes_1_1_3.PoamItem) *PoamItem {
	*p = PoamItem(op)
	return p
}

func (p *PoamItem) MarshalOscal() *oscalTypes_1_1_3.PoamItem {
	poamItem := oscalTypes_1_1_3.PoamItem(*p)
	return &poamItem
}
