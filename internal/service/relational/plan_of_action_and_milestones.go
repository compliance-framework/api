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

	// Simple fields stored as JSON
	ImportSsp        datatypes.JSONType[ImportSsp]              `json:"import-ssp"`
	SystemId         datatypes.JSONType[SystemId]               `json:"system-id"`
	LocalDefinitions *PlanOfActionAndMilestonesLocalDefinitions `json:"local-definitions" gorm:"type:json"`

	// Complex entities as proper tables with polymorphic relationships
	PoamItems    []PoamItem    `json:"poam-items" gorm:"foreignKey:PlanOfActionAndMilestonesID"`
	Observations []Observation `json:"observations" gorm:"polymorphic:Parent;"`
	Risks        []Risk        `json:"risks" gorm:"polymorphic:Parent;"`
	Findings     []Finding     `json:"findings" gorm:"polymorphic:Parent;"`
}

// UnmarshalOscal converts an OSCAL PlanOfActionAndMilestones into a relational PlanOfActionAndMilestones.
// It includes metadata, import-ssp, system-id, local-definitions, observations, risks, findings, poam-items, and back-matter.
func (p *PlanOfActionAndMilestones) UnmarshalOscal(opam oscalTypes_1_1_3.PlanOfActionAndMilestones) *PlanOfActionAndMilestones {
	metadata := &Metadata{}
	metadata.UnmarshalOscal(opam.Metadata)
	id := uuid.MustParse(opam.UUID)

	var importSsp datatypes.JSONType[ImportSsp]
	if opam.ImportSsp != nil {
		isp := ImportSsp{}
		isp.UnmarshalOscal(*opam.ImportSsp)
		importSsp = datatypes.NewJSONType(isp)
	}

	var systemId datatypes.JSONType[SystemId]
	if opam.SystemId != nil {
		sid := SystemId{}
		sid.UnmarshalOscal(*opam.SystemId)
		systemId = datatypes.NewJSONType(sid)
	}

	var localDefinitions *PlanOfActionAndMilestonesLocalDefinitions
	if opam.LocalDefinitions != nil {
		localDefinitions = &PlanOfActionAndMilestonesLocalDefinitions{}
		localDefinitions.UnmarshalOscal(*opam.LocalDefinitions)
	}

	var observations []Observation
	if opam.Observations != nil {
		observations = ConvertList(opam.Observations, func(o oscalTypes_1_1_3.Observation) Observation {
			obs := Observation{}
			obs.UnmarshalOscal(o, &id, "PlanOfActionAndMilestones")
			return obs
		})
	}

	var risks []Risk
	if opam.Risks != nil {
		risks = ConvertList(opam.Risks, func(or oscalTypes_1_1_3.Risk) Risk {
			r := Risk{}
			r.UnmarshalOscal(or, id, "PlanOfActionAndMilestones")
			return r
		})
	}

	var findings []Finding
	if opam.Findings != nil {
		findings = ConvertList(opam.Findings, func(of oscalTypes_1_1_3.Finding) Finding {
			f := Finding{}
			f.UnmarshalOscal(of, &id, "PlanOfActionAndMilestones")
			return f
		})
	}

	poamItems := ConvertList(&opam.PoamItems, func(opiam oscalTypes_1_1_3.PoamItem) PoamItem {
		poamItem := PoamItem{}
		poamItem.UnmarshalOscal(opiam, id)
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
		Metadata:         *metadata,
		ImportSsp:        importSsp,
		SystemId:         systemId,
		LocalDefinitions: localDefinitions,
		Observations:     observations,
		Risks:            risks,
		PoamItems:        poamItems,
		Findings:         findings,
		BackMatter:       backMatter,
	}
	return p
}

// MarshalOscal converts the relational PlanOfActionAndMilestones back into an OSCAL PlanOfActionAndMilestones structure.
func (p *PlanOfActionAndMilestones) MarshalOscal() *oscalTypes_1_1_3.PlanOfActionAndMilestones {
	opam := oscalTypes_1_1_3.PlanOfActionAndMilestones{
		UUID: p.UUIDModel.ID.String(),
	}

	opam.Metadata = *p.Metadata.MarshalOscal()

	if val, err := p.ImportSsp.Value(); err == nil && val != nil {
		isp := val.(ImportSsp)
		opam.ImportSsp = isp.MarshalOscal()
	}

	if val, err := p.SystemId.Value(); err == nil && val != nil {
		sid := val.(SystemId)
		opam.SystemId = sid.MarshalOscal()
	}

	if p.LocalDefinitions != nil {
		opam.LocalDefinitions = p.LocalDefinitions.MarshalOscal()
	}

	if len(p.Observations) > 0 {
		observations := make([]oscalTypes_1_1_3.Observation, len(p.Observations))
		for i, obs := range p.Observations {
			observations[i] = *obs.MarshalOscal()
		}
		opam.Observations = &observations
	}

	if len(p.Risks) > 0 {
		risks := make([]oscalTypes_1_1_3.Risk, len(p.Risks))
		for i, r := range p.Risks {
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

	if len(p.Findings) > 0 {
		findings := make([]oscalTypes_1_1_3.Finding, len(p.Findings))
		for i, f := range p.Findings {
			findings[i] = *f.MarshalOscal()
		}
		opam.Findings = &findings
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
	UUIDModel                                                                // required
	ParentID                    uuid.UUID                                    `gorm:"index"`               // Polymorphic parent reference
	ParentType                  string                                       `gorm:"index"`               // Polymorphic type (POAM or AssessmentResult)
	Title                       string                                       `json:"title"`               // required
	Description                 string                                       `json:"description"`         // required
	Statement                   string                                       `json:"statement"`           // required
	Status                      string                                       `json:"status" gorm:"index"` // required, indexed
	Props                       datatypes.JSONSlice[Prop]                    `json:"props"`
	Links                       datatypes.JSONSlice[Link]                    `json:"links"`
	Origins                     datatypes.JSONSlice[Origin]                  `json:"origins"`
	ThreatIds                   datatypes.JSONSlice[ThreatId]                `json:"threat-ids"`
	Characterizations           datatypes.JSONSlice[Characterization]        `json:"characterizations"`
	MitigatingFactors           datatypes.JSONSlice[MitigatingFactor]        `json:"mitigating-factors"`
	Deadline                    *time.Time                                   `json:"deadline" gorm:"index"` // Indexed for date queries
	Remediations                datatypes.JSONSlice[Response]                `json:"remediations"`
	RiskLog                     datatypes.JSONType[oscalTypes_1_1_3.RiskLog] `json:"risk-log"`
	RelatedObservations         datatypes.JSONSlice[RelatedObservation]      `json:"related-observations"`
}

// UnmarshalOscal converts an OSCAL Risk into a relational Risk.
func (r *Risk) UnmarshalOscal(or oscalTypes_1_1_3.Risk, parentID uuid.UUID, parentType string) *Risk {
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

	var riskLog datatypes.JSONType[oscalTypes_1_1_3.RiskLog]
	if or.RiskLog != nil {
		riskLog = datatypes.NewJSONType(*or.RiskLog)
	}

	*r = Risk{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ParentID:   parentID,
		ParentType: parentType,
		Title:                       or.Title,
		Description:                 or.Description,
		Statement:                   or.Statement,
		Status:                      or.Status,
		Props:                       props,
		Links:                       links,
		Origins:                     datatypes.NewJSONSlice(origins),
		ThreatIds:                   datatypes.NewJSONSlice(threatIds),
		Characterizations:           datatypes.NewJSONSlice(characterizations),
		MitigatingFactors:           datatypes.NewJSONSlice(mitigatingFactors),
		Deadline:                    or.Deadline,
		Remediations:                datatypes.NewJSONSlice(remediations),
		RiskLog:                     riskLog,
		RelatedObservations:         datatypes.NewJSONSlice(relatedObservations),
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

	if val, err := r.RiskLog.Value(); err == nil && val != nil {
		riskLog := val.(oscalTypes_1_1_3.RiskLog)
		ret.RiskLog = &riskLog
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
type PoamItem struct {
	PlanOfActionAndMilestonesID uuid.UUID                               `gorm:"primary_key"`
	UUID                        string                                  `json:"uuid" gorm:"primary_key"`
	Title                       string                                  `json:"title"`       // required
	Description                 string                                  `json:"description"` // required
	Props                       datatypes.JSONSlice[Prop]               `json:"props"`
	Links                       datatypes.JSONSlice[Link]               `json:"links"`
	Origins                     datatypes.JSONSlice[PoamItemOrigin]     `json:"origins"`
	RelatedFindings             datatypes.JSONSlice[RelatedFinding]     `json:"related-findings"`
	RelatedObservations         datatypes.JSONSlice[RelatedObservation] `json:"related-observations"`
	RelatedRisks                datatypes.JSONSlice[AssociatedRisk]     `json:"related-risks"`
	Remarks                     *string                                 `json:"remarks"`
}

func (p *PoamItem) UnmarshalOscal(op oscalTypes_1_1_3.PoamItem, planID uuid.UUID) *PoamItem {
	props := ConvertOscalToProps(op.Props)
	links := ConvertOscalToLinks(op.Links)

	origins := ConvertList(op.Origins, func(oo oscalTypes_1_1_3.PoamItemOrigin) PoamItemOrigin {
		origin := PoamItemOrigin{}
		origin.UnmarshalOscal(oo)
		return origin
	})

	relatedFindings := ConvertList(op.RelatedFindings, func(orf oscalTypes_1_1_3.RelatedFinding) RelatedFinding {
		relFinding := RelatedFinding{}
		relFinding.UnmarshalOscal(orf)
		return relFinding
	})

	relatedObservations := ConvertList(op.RelatedObservations, func(oro oscalTypes_1_1_3.RelatedObservation) RelatedObservation {
		relObs := RelatedObservation{}
		relObs.UnmarshalOscal(oro)
		return relObs
	})

	relatedRisks := ConvertList(op.RelatedRisks, func(oar oscalTypes_1_1_3.AssociatedRisk) AssociatedRisk {
		assocRisk := AssociatedRisk{}
		assocRisk.UnmarshalOscal(oar)
		return assocRisk
	})

	*p = PoamItem{
		PlanOfActionAndMilestonesID: planID,
		UUID:                        op.UUID,
		Title:                       op.Title,
		Description:                 op.Description,
		Props:                       props,
		Links:                       links,
		Origins:                     datatypes.NewJSONSlice(origins),
		RelatedFindings:             datatypes.NewJSONSlice(relatedFindings),
		RelatedObservations:         datatypes.NewJSONSlice(relatedObservations),
		RelatedRisks:                datatypes.NewJSONSlice(relatedRisks),
		Remarks:                     &op.Remarks,
	}
	return p
}

func (p *PoamItem) MarshalOscal() *oscalTypes_1_1_3.PoamItem {
	ret := oscalTypes_1_1_3.PoamItem{
		UUID:        p.UUID,
		Title:       p.Title,
		Description: p.Description,
	}

	if len(p.Props) > 0 {
		ret.Props = ConvertPropsToOscal(p.Props)
	}

	if len(p.Links) > 0 {
		ret.Links = ConvertLinksToOscal(p.Links)
	}

	if len(p.Origins) > 0 {
		origins := make([]oscalTypes_1_1_3.PoamItemOrigin, len(p.Origins))
		for i, origin := range p.Origins {
			origins[i] = *origin.MarshalOscal()
		}
		ret.Origins = &origins
	}

	if len(p.RelatedFindings) > 0 {
		relatedFindings := make([]oscalTypes_1_1_3.RelatedFinding, len(p.RelatedFindings))
		for i, relFinding := range p.RelatedFindings {
			relatedFindings[i] = *relFinding.MarshalOscal()
		}
		ret.RelatedFindings = &relatedFindings
	}

	if len(p.RelatedObservations) > 0 {
		relatedObservations := make([]oscalTypes_1_1_3.RelatedObservation, len(p.RelatedObservations))
		for i, relObs := range p.RelatedObservations {
			relatedObservations[i] = *relObs.MarshalOscal()
		}
		ret.RelatedObservations = &relatedObservations
	}

	if len(p.RelatedRisks) > 0 {
		relatedRisks := make([]oscalTypes_1_1_3.AssociatedRisk, len(p.RelatedRisks))
		for i, assocRisk := range p.RelatedRisks {
			relatedRisks[i] = *assocRisk.MarshalOscal()
		}
		ret.RelatedRisks = &relatedRisks
	}

	if p.Remarks != nil {
		ret.Remarks = *p.Remarks
	}

	return &ret
}

// PlanOfActionAndMilestonesLocalDefinitions represents local definitions in POAM.
type PlanOfActionAndMilestonesLocalDefinitions struct {
	AssessmentAssets datatypes.JSONType[oscalTypes_1_1_3.AssessmentAssets] `json:"assessment-assets"`
	Components       datatypes.JSONSlice[oscalTypes_1_1_3.SystemComponent] `json:"components" gorm:"type:json"`
	InventoryItems   datatypes.JSONSlice[oscalTypes_1_1_3.InventoryItem]   `json:"inventory-items" gorm:"type:json"`
	Remarks          string                                                `json:"remarks"`
}

func (p *PlanOfActionAndMilestonesLocalDefinitions) UnmarshalOscal(op oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions) *PlanOfActionAndMilestonesLocalDefinitions {
	var assessmentAssets datatypes.JSONType[oscalTypes_1_1_3.AssessmentAssets]
	if op.AssessmentAssets != nil {
		assessmentAssets = datatypes.NewJSONType(*op.AssessmentAssets)
	}

	components := ConvertList(op.Components, func(oc oscalTypes_1_1_3.SystemComponent) oscalTypes_1_1_3.SystemComponent {
		return oc
	})

	inventoryItems := ConvertList(op.InventoryItems, func(oi oscalTypes_1_1_3.InventoryItem) oscalTypes_1_1_3.InventoryItem {
		return oi
	})

	*p = PlanOfActionAndMilestonesLocalDefinitions{
		AssessmentAssets: assessmentAssets,
		Components:       datatypes.NewJSONSlice(components),
		InventoryItems:   datatypes.NewJSONSlice(inventoryItems),
		Remarks:          op.Remarks,
	}
	return p
}

func (p *PlanOfActionAndMilestonesLocalDefinitions) MarshalOscal() *oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions {
	ret := oscalTypes_1_1_3.PlanOfActionAndMilestonesLocalDefinitions{
		Remarks: p.Remarks,
	}

	if val, err := p.AssessmentAssets.Value(); err == nil && val != nil {
		assessmentAssets := val.(oscalTypes_1_1_3.AssessmentAssets)
		ret.AssessmentAssets = &assessmentAssets
	}

	if len(p.Components) > 0 {
		components := make([]oscalTypes_1_1_3.SystemComponent, len(p.Components))
		for i, comp := range p.Components {
			components[i] = comp
		}
		ret.Components = &components
	}

	if len(p.InventoryItems) > 0 {
		items := make([]oscalTypes_1_1_3.InventoryItem, len(p.InventoryItems))
		for i, item := range p.InventoryItems {
			items[i] = item
		}
		ret.InventoryItems = &items
	}

	return &ret
}

// Observation represents an observation in OSCAL.
type Observation struct {
	UUIDModel                                                         // required
	ParentID                    *uuid.UUID                            `gorm:"index"`                      // Polymorphic parent reference (optional)
	ParentType                  string                                `gorm:"index"`                      // Polymorphic type (POAM or AssessmentResult)
	Collected                   time.Time                             `json:"collected" gorm:"index"`     // required, indexed
	Description                 string                                `json:"description"`                // required
	Methods                     []string                              `gorm:"type:text[]" json:"methods"` // required, PostgreSQL array
	Expires                     *time.Time                            `json:"expires" gorm:"index"`       // Indexed for date queries
	Links                       datatypes.JSONSlice[Link]             `json:"links"`
	Origins                     datatypes.JSONSlice[Origin]           `json:"origins"`
	Props                       datatypes.JSONSlice[Prop]             `json:"props"`
	RelevantEvidence            datatypes.JSONSlice[RelevantEvidence] `json:"relevant-evidence"`
	Remarks                     *string                               `json:"remarks"`
	Subjects                    datatypes.JSONSlice[SubjectReference] `json:"subjects"`
	Title                       *string                               `json:"title"`
	Types                       []string                              `gorm:"type:text[]" json:"types"` // PostgreSQL array
}

func (o *Observation) UnmarshalOscal(oo oscalTypes_1_1_3.Observation, parentID *uuid.UUID, parentType string) *Observation {
	id := uuid.MustParse(oo.UUID)

	links := ConvertOscalToLinks(oo.Links)
	props := ConvertOscalToProps(oo.Props)

	origins := ConvertList(oo.Origins, func(oor oscalTypes_1_1_3.Origin) Origin {
		origin := Origin{}
		origin.UnmarshalOscal(oor)
		return origin
	})

	relevantEvidence := ConvertList(oo.RelevantEvidence, func(ore oscalTypes_1_1_3.RelevantEvidence) RelevantEvidence {
		evidence := RelevantEvidence{}
		evidence.UnmarshalOscal(ore)
		return evidence
	})

	subjects := ConvertList(oo.Subjects, func(os oscalTypes_1_1_3.SubjectReference) SubjectReference {
		subject := SubjectReference{}
		subject.UnmarshalOscal(os)
		return subject
	})

	var types []string
	if oo.Types != nil {
		types = *oo.Types
	}

	*o = Observation{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ParentID:   parentID,
		ParentType: parentType,
		Collected:                   oo.Collected,
		Description:                 oo.Description,
		Methods:                     oo.Methods,
		Expires:                     oo.Expires,
		Links:                       links,
		Origins:                     datatypes.NewJSONSlice(origins),
		Props:                       props,
		RelevantEvidence:            datatypes.NewJSONSlice(relevantEvidence),
		Remarks:                     &oo.Remarks,
		Subjects:                    datatypes.NewJSONSlice(subjects),
		Title:                       &oo.Title,
		Types:                       types,
	}
	return o
}

func (o *Observation) MarshalOscal() *oscalTypes_1_1_3.Observation {
	ret := oscalTypes_1_1_3.Observation{
		UUID:        o.UUIDModel.ID.String(),
		Collected:   o.Collected,
		Description: o.Description,
		Methods:     o.Methods,
	}

	if o.Expires != nil {
		ret.Expires = o.Expires
	}

	if len(o.Links) > 0 {
		ret.Links = ConvertLinksToOscal(o.Links)
	}

	if len(o.Origins) > 0 {
		origins := make([]oscalTypes_1_1_3.Origin, len(o.Origins))
		for i, origin := range o.Origins {
			origins[i] = *origin.MarshalOscal()
		}
		ret.Origins = &origins
	}

	if len(o.Props) > 0 {
		ret.Props = ConvertPropsToOscal(o.Props)
	}

	if len(o.RelevantEvidence) > 0 {
		evidence := make([]oscalTypes_1_1_3.RelevantEvidence, len(o.RelevantEvidence))
		for i, ev := range o.RelevantEvidence {
			evidence[i] = *ev.MarshalOscal()
		}
		ret.RelevantEvidence = &evidence
	}

	if o.Remarks != nil && *o.Remarks != "" {
		ret.Remarks = *o.Remarks
	}

	if len(o.Subjects) > 0 {
		subjects := make([]oscalTypes_1_1_3.SubjectReference, len(o.Subjects))
		for i, subject := range o.Subjects {
			subjects[i] = *subject.MarshalOscal()
		}
		ret.Subjects = &subjects
	}

	if o.Title != nil && *o.Title != "" {
		ret.Title = *o.Title
	}

	if len(o.Types) > 0 {
		ret.Types = &o.Types
	}

	return &ret
}

// Finding represents a finding in OSCAL.
type Finding struct {
	UUIDModel                                                                      // required
	ParentID                    *uuid.UUID                                         `gorm:"index"`       // Polymorphic parent reference (optional)
	ParentType                  string                                             `gorm:"index"`       // Polymorphic type (POAM or AssessmentResult)
	Description                 string                                             `json:"description"` // required
	Title                       string                                             `json:"title"`       // required
	Target                      datatypes.JSONType[oscalTypes_1_1_3.FindingTarget] `json:"target"`      // required
	ImplementationStatementUuid *string                                            `json:"implementation-statement-uuid"`
	Links                       datatypes.JSONSlice[Link]                          `json:"links"`
	Origins                     datatypes.JSONSlice[Origin]                        `json:"origins"`
	Props                       datatypes.JSONSlice[Prop]                          `json:"props"`
	RelatedObservations         datatypes.JSONSlice[RelatedObservation]            `json:"related-observations"`
	RelatedRisks                datatypes.JSONSlice[AssociatedRisk]                `json:"related-risks"`
	Remarks                     *string                                            `json:"remarks"`
}

func (f *Finding) UnmarshalOscal(of oscalTypes_1_1_3.Finding, parentID *uuid.UUID, parentType string) *Finding {
	id := uuid.MustParse(of.UUID)

	links := ConvertOscalToLinks(of.Links)
	props := ConvertOscalToProps(of.Props)

	origins := ConvertList(of.Origins, func(oo oscalTypes_1_1_3.Origin) Origin {
		origin := Origin{}
		origin.UnmarshalOscal(oo)
		return origin
	})

	relatedObservations := ConvertList(of.RelatedObservations, func(oro oscalTypes_1_1_3.RelatedObservation) RelatedObservation {
		relObs := RelatedObservation{}
		relObs.UnmarshalOscal(oro)
		return relObs
	})

	relatedRisks := ConvertList(of.RelatedRisks, func(oar oscalTypes_1_1_3.AssociatedRisk) AssociatedRisk {
		assocRisk := AssociatedRisk{}
		assocRisk.UnmarshalOscal(oar)
		return assocRisk
	})

	target := datatypes.NewJSONType(of.Target)

	*f = Finding{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ParentID:   parentID,
		ParentType: parentType,
		Description:                 of.Description,
		Title:                       of.Title,
		Target:                      target,
		ImplementationStatementUuid: &of.ImplementationStatementUuid,
		Links:                       links,
		Origins:                     datatypes.NewJSONSlice(origins),
		Props:                       props,
		RelatedObservations:         datatypes.NewJSONSlice(relatedObservations),
		RelatedRisks:                datatypes.NewJSONSlice(relatedRisks),
		Remarks:                     &of.Remarks,
	}
	return f
}

func (f *Finding) MarshalOscal() *oscalTypes_1_1_3.Finding {
	ret := oscalTypes_1_1_3.Finding{
		UUID:        f.UUIDModel.ID.String(),
		Description: f.Description,
		Title:       f.Title,
		Target:      f.Target.Data(),
	}

	if f.ImplementationStatementUuid != nil && *f.ImplementationStatementUuid != "" {
		ret.ImplementationStatementUuid = *f.ImplementationStatementUuid
	}

	if len(f.Links) > 0 {
		ret.Links = ConvertLinksToOscal(f.Links)
	}

	if len(f.Origins) > 0 {
		origins := make([]oscalTypes_1_1_3.Origin, len(f.Origins))
		for i, origin := range f.Origins {
			origins[i] = *origin.MarshalOscal()
		}
		ret.Origins = &origins
	}

	if len(f.Props) > 0 {
		ret.Props = ConvertPropsToOscal(f.Props)
	}

	if len(f.RelatedObservations) > 0 {
		relatedObservations := make([]oscalTypes_1_1_3.RelatedObservation, len(f.RelatedObservations))
		for i, relObs := range f.RelatedObservations {
			relatedObservations[i] = *relObs.MarshalOscal()
		}
		ret.RelatedObservations = &relatedObservations
	}

	if len(f.RelatedRisks) > 0 {
		relatedRisks := make([]oscalTypes_1_1_3.AssociatedRisk, len(f.RelatedRisks))
		for i, assocRisk := range f.RelatedRisks {
			relatedRisks[i] = *assocRisk.MarshalOscal()
		}
		ret.RelatedRisks = &relatedRisks
	}

	if f.Remarks != nil && *f.Remarks != "" {
		ret.Remarks = *f.Remarks
	}

	return &ret
}

// Supporting types for the POAM structure

// AssessmentAssets represents assessment assets in OSCAL.
type AssessmentAssets oscalTypes_1_1_3.AssessmentAssets

func (a *AssessmentAssets) UnmarshalOscal(oa oscalTypes_1_1_3.AssessmentAssets) *AssessmentAssets {
	*a = AssessmentAssets(oa)
	return a
}

func (a *AssessmentAssets) MarshalOscal() *oscalTypes_1_1_3.AssessmentAssets {
	assets := oscalTypes_1_1_3.AssessmentAssets(*a)
	return &assets
}

// RelevantEvidence represents relevant evidence in OSCAL.
type RelevantEvidence oscalTypes_1_1_3.RelevantEvidence

func (r *RelevantEvidence) UnmarshalOscal(ore oscalTypes_1_1_3.RelevantEvidence) *RelevantEvidence {
	*r = RelevantEvidence(ore)
	return r
}

func (r *RelevantEvidence) MarshalOscal() *oscalTypes_1_1_3.RelevantEvidence {
	evidence := oscalTypes_1_1_3.RelevantEvidence(*r)
	return &evidence
}

// SubjectReference represents a subject reference in OSCAL.
type SubjectReference oscalTypes_1_1_3.SubjectReference

func (s *SubjectReference) UnmarshalOscal(os oscalTypes_1_1_3.SubjectReference) *SubjectReference {
	*s = SubjectReference(os)
	return s
}

func (s *SubjectReference) MarshalOscal() *oscalTypes_1_1_3.SubjectReference {
	subjectRef := oscalTypes_1_1_3.SubjectReference(*s)
	return &subjectRef
}

// FindingTarget represents a finding target in OSCAL.
type FindingTarget oscalTypes_1_1_3.FindingTarget

func (f *FindingTarget) UnmarshalOscal(of oscalTypes_1_1_3.FindingTarget) *FindingTarget {
	*f = FindingTarget(of)
	return f
}

func (f *FindingTarget) MarshalOscal() *oscalTypes_1_1_3.FindingTarget {
	target := oscalTypes_1_1_3.FindingTarget(*f)
	return &target
}

// AssociatedRisk represents an associated risk in OSCAL.
type AssociatedRisk oscalTypes_1_1_3.AssociatedRisk

func (a *AssociatedRisk) UnmarshalOscal(oar oscalTypes_1_1_3.AssociatedRisk) *AssociatedRisk {
	*a = AssociatedRisk(oar)
	return a
}

func (a *AssociatedRisk) MarshalOscal() *oscalTypes_1_1_3.AssociatedRisk {
	risk := oscalTypes_1_1_3.AssociatedRisk(*a)
	return &risk
}

// RelatedFinding represents a related finding in OSCAL.
type RelatedFinding oscalTypes_1_1_3.RelatedFinding

func (r *RelatedFinding) UnmarshalOscal(orf oscalTypes_1_1_3.RelatedFinding) *RelatedFinding {
	*r = RelatedFinding(orf)
	return r
}

func (r *RelatedFinding) MarshalOscal() *oscalTypes_1_1_3.RelatedFinding {
	finding := oscalTypes_1_1_3.RelatedFinding(*r)
	return &finding
}

// PoamItemOrigin represents a POAM item origin in OSCAL.
type PoamItemOrigin oscalTypes_1_1_3.PoamItemOrigin

func (p *PoamItemOrigin) UnmarshalOscal(op oscalTypes_1_1_3.PoamItemOrigin) *PoamItemOrigin {
	*p = PoamItemOrigin(op)
	return p
}

func (p *PoamItemOrigin) MarshalOscal() *oscalTypes_1_1_3.PoamItemOrigin {
	origin := oscalTypes_1_1_3.PoamItemOrigin(*p)
	return &origin
}
