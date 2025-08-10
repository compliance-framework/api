package relational

import (
	"time"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type AssessmentPlan struct {
	UUIDModel
	Metadata   Metadata    `gorm:"polymorphic:Parent;"`
	BackMatter *BackMatter `gorm:"polymorphic:Parent;"`
	ImportSSP  datatypes.JSONType[ImportSsp]

	Tasks []Task `gorm:"polymorphic:Parent"`

	ReviewedControlsID uuid.UUID
	ReviewedControls   ReviewedControls

	AssessmentAssetsID *uuid.UUID
	AssessmentAssets   *AssessmentAsset
	AssessmentSubjects []AssessmentSubject `gorm:"many2many:assessment_plan_assessment_subjects"`
	LocalDefinitions   LocalDefinitions    `gorm:"polymorphic:Parent"`

	TermsAndConditionsID *uuid.UUID
	TermsAndConditions   *TermsAndConditions
}

func (i *AssessmentPlan) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentPlan) *AssessmentPlan {
	id := uuid.MustParse(op.UUID)
	*i = AssessmentPlan{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		ImportSSP: datatypes.NewJSONType(ImportSsp(op.ImportSsp)),
		Metadata:  *(&Metadata{}).UnmarshalOscal(op.Metadata),
	}
	// Metadata and BackMatter are polymorphic, skip for now or implement if necessary
	// Tasks
	if op.Tasks != nil {
		i.Tasks = make([]Task, len(*op.Tasks))
		for idx, t := range *op.Tasks {
			i.Tasks[idx] = *(&Task{}).UnmarshalOscal(t)
		}
	}
	// ReviewedControls
	i.ReviewedControls = *(&ReviewedControls{}).UnmarshalOscal(op.ReviewedControls)

	// AssessmentAssets
	if op.AssessmentAssets != nil {
		i.AssessmentAssets = (&AssessmentAsset{}).UnmarshalOscal(*op.AssessmentAssets)
		i.AssessmentAssets.ParentID = *i.ID
		i.AssessmentAssets.ParentType = "assessment_plan"
	}
	// AssessmentSubjects
	if op.AssessmentSubjects != nil {
		i.AssessmentSubjects = make([]AssessmentSubject, len(*op.AssessmentSubjects))
		for idx, s := range *op.AssessmentSubjects {
			i.AssessmentSubjects[idx] = *(&AssessmentSubject{}).UnmarshalOscal(s)
		}
	}
	// LocalDefinitions
	if op.LocalDefinitions != nil {
		i.LocalDefinitions = *(&LocalDefinitions{}).UnmarshalOscal(*op.LocalDefinitions)
	}
	// TermsAndConditions
	if op.TermsAndConditions != nil {
		i.TermsAndConditions = (&TermsAndConditions{}).UnmarshalOscal(*op.TermsAndConditions)
	}
	return i
}

func (i *AssessmentPlan) MarshalOscal() *oscalTypes_1_1_3.AssessmentPlan {
	ret := oscalTypes_1_1_3.AssessmentPlan{
		UUID:             i.ID.String(),
		ImportSsp:        oscalTypes_1_1_3.ImportSsp(i.ImportSSP.Data()),
		Metadata:         *i.Metadata.MarshalOscal(),
		ReviewedControls: *i.ReviewedControls.MarshalOscal(),
		LocalDefinitions: i.LocalDefinitions.MarshalOscal(),
	}

	// TermsAndConditions - check for proper initialization before marshaling
	if i.TermsAndConditions != nil {
		ret.TermsAndConditions = i.TermsAndConditions.MarshalOscal()
	}

	// AssessmentAssets - check for nil before marshaling
	if i.AssessmentAssets != nil {
		ret.AssessmentAssets = i.AssessmentAssets.MarshalOscal()
	}

	// Tasks
	if len(i.Tasks) > 0 {
		tasks := make([]oscalTypes_1_1_3.Task, len(i.Tasks))
		for idx := range i.Tasks {
			tasks[idx] = *i.Tasks[idx].MarshalOscal()
		}
		ret.Tasks = &tasks
	}

	// AssessmentSubjects
	if len(i.AssessmentSubjects) > 0 {
		subjs := make([]oscalTypes_1_1_3.AssessmentSubject, len(i.AssessmentSubjects))
		for idx := range i.AssessmentSubjects {
			subjs[idx] = *i.AssessmentSubjects[idx].MarshalOscal()
		}
		ret.AssessmentSubjects = &subjs
	}

	return &ret
}

type AssessmentResult struct {
	UUIDModel
	Metadata   Metadata    `gorm:"polymorphic:Parent;"`
	BackMatter *BackMatter `gorm:"polymorphic:Parent;"`
	ImportAp   datatypes.JSONType[ImportAp]

	LocalDefinitions *LocalDefinitions `gorm:"polymorphic:Parent"`
	Results          []Result
}

func (i *AssessmentResult) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentResults) *AssessmentResult {
	id := uuid.MustParse(op.UUID)
	*i = AssessmentResult{
		ImportAp: datatypes.NewJSONType(*(&ImportAp{}).UnmarshalOscal(op.ImportAp)),
		Metadata: *(&Metadata{}).UnmarshalOscal(op.Metadata),
		UUIDModel: UUIDModel{
			ID: &id,
		},
	}
	// LocalDefinitions
	if op.LocalDefinitions != nil {
		i.LocalDefinitions = (&LocalDefinitions{}).UnmarshalOscal(*op.LocalDefinitions)
	}
	// Results
	if op.Results != nil {
		i.Results = make([]Result, len(op.Results))
		for idx, r := range op.Results {
			i.Results[idx] = *(&Result{}).UnmarshalOscal(r)
		}
	}
	return i
}

func (i *AssessmentResult) MarshalOscal() *oscalTypes_1_1_3.AssessmentResults {
	ret := oscalTypes_1_1_3.AssessmentResults{
		ImportAp: oscalTypes_1_1_3.ImportAp(i.ImportAp.Data()),
		Metadata: *i.Metadata.MarshalOscal(),
		UUID:     i.ID.String(),
	}

	// Only set LocalDefinitions if it's not nil
	if i.LocalDefinitions != nil {
		ret.LocalDefinitions = i.LocalDefinitions.MarshalOscal()
	}

	// Results
	if len(i.Results) > 0 {
		res := make([]oscalTypes_1_1_3.Result, len(i.Results))
		for idx := range i.Results {
			res[idx] = *i.Results[idx].MarshalOscal()
		}
		ret.Results = res
	}
	return &ret
}

type Result struct {
	UUIDModel
	AssessmentResultID uuid.UUID
	Title              string // required
	Description        string // required
	Remarks            *string
	Start              *time.Time
	End                *time.Time
	Props              datatypes.JSONSlice[Prop]
	Links              datatypes.JSONSlice[Link]
	LocalDefinitionsID uuid.UUID
	LocalDefinitions   LocalDefinitions
	ReviewedControlsID uuid.UUID
	ReviewedControls   ReviewedControls
	Attestations       []Attestation
	AssessmentLogID    *uuid.UUID
	AssessmentLog      *AssessmentLog

	// Shared entities now using polymorphic associations
	Observations []Observation `gorm:"many2many:result_observations;"`
	Findings     []Finding     `gorm:"many2many:result_findings;"`
	Risks        []Risk        `gorm:"many2many:result_risks;"`
}

func (i *Result) UnmarshalOscal(op oscalTypes_1_1_3.Result) *Result {
	id := uuid.MustParse(op.UUID)
	*i = Result{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Title:            op.Title,
		Description:      op.Description,
		Remarks:          &op.Remarks,
		Start:            &op.Start,
		End:              op.End,
		ReviewedControls: *(&ReviewedControls{}).UnmarshalOscal(op.ReviewedControls),
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	// LocalDefinitions
	if op.LocalDefinitions != nil {
		i.LocalDefinitions = *(&LocalDefinitions{}).UnmarshalOscal(*op.LocalDefinitions)
	}
	// Attestations
	if op.Attestations != nil {
		i.Attestations = make([]Attestation, len(*op.Attestations))
		for idx, a := range *op.Attestations {
			i.Attestations[idx] = *(&Attestation{}).UnmarshalOscal(a)
		}
	}
	// AssessmentLogs
	if op.AssessmentLog != nil {
		i.AssessmentLog = (&AssessmentLog{}).UnmarshalOscal(*op.AssessmentLog)
	}
	// Observations
	if op.Observations != nil {
		i.Observations = make([]Observation, len(*op.Observations))
		for idx, obs := range *op.Observations {
			i.Observations[idx] = *(&Observation{}).UnmarshalOscal(obs)
		}
	}
	// Findings
	if op.Findings != nil {
		i.Findings = make([]Finding, len(*op.Findings))
		for idx, finding := range *op.Findings {
			i.Findings[idx] = *(&Finding{}).UnmarshalOscal(finding)
		}
	}
	// Risks
	if op.Risks != nil {
		i.Risks = make([]Risk, len(*op.Risks))
		for idx, risk := range *op.Risks {
			i.Risks[idx] = *(&Risk{}).UnmarshalOscal(risk)
		}
	}
	return i
}

func (i *Result) MarshalOscal() *oscalTypes_1_1_3.Result {
	ret := oscalTypes_1_1_3.Result{
		UUID:        i.ID.String(),
		Title:       i.Title,
		Description: i.Description,
		// LocalDefinitions
		LocalDefinitions: i.LocalDefinitions.MarshalOscal(),
		// ReviewedControls
		ReviewedControls: *i.ReviewedControls.MarshalOscal(),
	}
	if i.Remarks != nil {
		ret.Remarks = *i.Remarks
	}
	if i.Start != nil {
		ret.Start = *i.Start
	}
	if i.End != nil {
		ret.End = i.End
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}

	// Attestations
	if len(i.Attestations) > 0 {
		att := make([]oscalTypes_1_1_3.AttestationStatements, len(i.Attestations))
		for idx := range i.Attestations {
			att[idx] = *i.Attestations[idx].MarshalOscal()
		}
		ret.Attestations = &att
	}
	// AssessmentLogs
	if i.AssessmentLog != nil {
		ret.AssessmentLog = i.AssessmentLog.MarshalOscal()
	}
	// Observations
	if len(i.Observations) > 0 {
		observations := make([]oscalTypes_1_1_3.Observation, len(i.Observations))
		for idx, obs := range i.Observations {
			observations[idx] = *obs.MarshalOscal()
		}
		ret.Observations = &observations
	}
	// Findings
	if len(i.Findings) > 0 {
		findings := make([]oscalTypes_1_1_3.Finding, len(i.Findings))
		for idx, finding := range i.Findings {
			findings[idx] = *finding.MarshalOscal()
		}
		ret.Findings = &findings
	}
	// Risks
	if len(i.Risks) > 0 {
		risks := make([]oscalTypes_1_1_3.Risk, len(i.Risks))
		for idx, risk := range i.Risks {
			risks[idx] = *risk.MarshalOscal()
		}
		ret.Risks = &risks
	}
	return &ret
}

type AssessmentLog struct {
	UUIDModel
	Entries []AssessmentLogEntry
}

func (i *AssessmentLog) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentLog) *AssessmentLog {
	*i = AssessmentLog{}
	// Entries
	if op.Entries != nil {
		i.Entries = make([]AssessmentLogEntry, len(op.Entries))
		for idx, e := range op.Entries {
			i.Entries[idx] = *(&AssessmentLogEntry{}).UnmarshalOscal(e)
		}
	}
	return i
}

func (i *AssessmentLog) MarshalOscal() *oscalTypes_1_1_3.AssessmentLog {
	ret := oscalTypes_1_1_3.AssessmentLog{}
	// Entries
	if len(i.Entries) > 0 {
		entries := make([]oscalTypes_1_1_3.AssessmentLogEntry, len(i.Entries))
		for idx := range i.Entries {
			entries[idx] = *i.Entries[idx].MarshalOscal()
		}
		ret.Entries = entries
	}
	return &ret
}

type AssessmentLogEntry struct {
	UUIDModel
	AssessmentLogID uuid.UUID

	Title       *string
	Remarks     *string
	Description *string
	Start       *time.Time
	End         *time.Time

	Props        datatypes.JSONSlice[Prop]
	Links        datatypes.JSONSlice[Link]
	LoggedBy     []LoggedBy    `gorm:"polymorphic:Parent"`
	RelatedTasks []RelatedTask `gorm:"polymorphic:Parent"`
}

func (i *AssessmentLogEntry) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentLogEntry) *AssessmentLogEntry {
	*i = AssessmentLogEntry{
		Title:       &op.Title,
		Description: &op.Description,
		Remarks:     &op.Remarks,
		Start:       &op.Start,
	}
	if op.End != nil {
		i.End = op.End
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	// LoggedBy
	if op.LoggedBy != nil {
		i.LoggedBy = make([]LoggedBy, len(*op.LoggedBy))
		for idx, lb := range *op.LoggedBy {
			i.LoggedBy[idx] = *(&LoggedBy{}).UnmarshalOscal(lb)
		}
	}
	// RelatedTasks
	if op.RelatedTasks != nil {
		i.RelatedTasks = make([]RelatedTask, len(*op.RelatedTasks))
		for idx, rt := range *op.RelatedTasks {
			i.RelatedTasks[idx] = *(&RelatedTask{}).UnmarshalOscal(rt)
		}
	}
	return i
}

func (i *AssessmentLogEntry) MarshalOscal() *oscalTypes_1_1_3.AssessmentLogEntry {
	ret := oscalTypes_1_1_3.AssessmentLogEntry{
		Title:       *i.Title,
		Remarks:     *i.Remarks,
		Description: *i.Description,
	}
	if i.Start != nil {
		ret.Start = *i.Start
	}
	if i.End != nil {
		ret.End = i.End
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	// LoggedBy
	if len(i.LoggedBy) > 0 {
		lbs := make([]oscalTypes_1_1_3.LoggedBy, len(i.LoggedBy))
		for idx := range i.LoggedBy {
			lbs[idx] = *i.LoggedBy[idx].MarshalOscal()
		}
		ret.LoggedBy = &lbs
	}
	// RelatedTasks
	if len(i.RelatedTasks) > 0 {
		rts := make([]oscalTypes_1_1_3.RelatedTask, len(i.RelatedTasks))
		for idx := range i.RelatedTasks {
			rts[idx] = *i.RelatedTasks[idx].MarshalOscal()
		}
		ret.RelatedTasks = &rts
	}
	return &ret
}

type LoggedBy struct {
	PartyID uuid.UUID
	Party   Party

	RoleID string
	Role   Role

	ParentType string
	ParentID   uuid.UUID
}

func (i *LoggedBy) UnmarshalOscal(op oscalTypes_1_1_3.LoggedBy) *LoggedBy {
	*i = LoggedBy{
		PartyID: uuid.MustParse(op.PartyUuid),
		RoleID:  op.RoleId,
	}
	return i
}

func (i *LoggedBy) MarshalOscal() *oscalTypes_1_1_3.LoggedBy {
	return &oscalTypes_1_1_3.LoggedBy{
		PartyUuid: i.PartyID.String(),
		RoleId:    i.RoleID,
	}
}

type RelatedTask struct {
	UUIDModel
	Task               Task
	TaskID             uuid.UUID
	Remarks            *string
	Props              datatypes.JSONSlice[Prop]
	Links              datatypes.JSONSlice[Link]
	ResponsibleParties []ResponsibleParty  `gorm:"many2many:related_task_responsible_parties;"`
	Subjects           []AssessmentSubject `gorm:"many2many:related_task_subjects;"`
	IdentifiedSubject  *IdentifiedSubject

	ParentType string
	ParentID   uuid.UUID
}

func (i *RelatedTask) UnmarshalOscal(op oscalTypes_1_1_3.RelatedTask) *RelatedTask {
	*i = RelatedTask{
		TaskID:  uuid.MustParse(op.TaskUuid),
		Remarks: &op.Remarks,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	// ResponsibleParties
	if op.ResponsibleParties != nil {
		i.ResponsibleParties = make([]ResponsibleParty, len(*op.ResponsibleParties))
		for idx, rp := range *op.ResponsibleParties {
			i.ResponsibleParties[idx] = *(&ResponsibleParty{}).UnmarshalOscal(rp)
		}
	}
	// Subjects
	if op.Subjects != nil {
		i.Subjects = make([]AssessmentSubject, len(*op.Subjects))
		for idx, s := range *op.Subjects {
			i.Subjects[idx] = *(&AssessmentSubject{}).UnmarshalOscal(s)
		}
	}
	// IdentifiedSubject
	if op.IdentifiedSubject != nil {
		i.IdentifiedSubject = &IdentifiedSubject{}
		i.IdentifiedSubject.UnmarshalOscal(*op.IdentifiedSubject)
	}
	return i
}

func (i *RelatedTask) MarshalOscal() *oscalTypes_1_1_3.RelatedTask {
	ret := &oscalTypes_1_1_3.RelatedTask{
		TaskUuid: i.TaskID.String(),
		Remarks:  *i.Remarks,
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if len(i.ResponsibleParties) > 0 {
		rps := make([]oscalTypes_1_1_3.ResponsibleParty, len(i.ResponsibleParties))
		for idx := range i.ResponsibleParties {
			rps[idx] = *i.ResponsibleParties[idx].MarshalOscal()
		}
		ret.ResponsibleParties = &rps
	}
	if i.IdentifiedSubject != nil {
		is := i.IdentifiedSubject.MarshalOscal()
		ret.IdentifiedSubject = is
	}
	return ret
}

type IdentifiedSubject struct {
	UUIDModel
	RelatedTaskID        uuid.UUID
	SubjectPlaceholderID uuid.UUID
	Subjects             []AssessmentSubject `gorm:"many2many:related_task_subjects;"`
}

func (i *IdentifiedSubject) UnmarshalOscal(op oscalTypes_1_1_3.IdentifiedSubject) *IdentifiedSubject {
	*i = IdentifiedSubject{}
	// Subjects
	if op.Subjects != nil {
		i.Subjects = make([]AssessmentSubject, len(op.Subjects))
		for idx, s := range op.Subjects {
			i.Subjects[idx] = *(&AssessmentSubject{}).UnmarshalOscal(s)
		}
	}
	return i
}

func (i *IdentifiedSubject) MarshalOscal() *oscalTypes_1_1_3.IdentifiedSubject {
	ret := &oscalTypes_1_1_3.IdentifiedSubject{}
	if len(i.Subjects) > 0 {
		subs := make([]oscalTypes_1_1_3.AssessmentSubject, len(i.Subjects))
		for idx := range i.Subjects {
			subs[idx] = *i.Subjects[idx].MarshalOscal()
		}
		ret.Subjects = subs
	}
	return ret
}

type Attestation struct {
	UUIDModel
	ResultID           uuid.UUID
	ResponsibleParties []ResponsibleParty                  `gorm:"many2many:attestation_responsible_parties"`
	Parts              datatypes.JSONSlice[AssessmentPart] // required
}

func (i *Attestation) UnmarshalOscal(op oscalTypes_1_1_3.AttestationStatements) *Attestation {
	// Preserve existing ID and ResultID if they exist
	existingID := i.ID
	existingResultID := i.ResultID

	// Zero the struct first
	*i = Attestation{}

	// Now restore the preserved values
	i.ID = existingID
	i.ResultID = existingResultID

	if op.Parts != nil {
		parts := ConvertList(&op.Parts, func(data oscalTypes_1_1_3.AssessmentPart) AssessmentPart {
			output := AssessmentPart{}
			output.UnmarshalOscal(data)
			return output
		})
		i.Parts = parts
	}
	// ResponsibleParties
	if op.ResponsibleParties != nil {
		i.ResponsibleParties = make([]ResponsibleParty, len(*op.ResponsibleParties))
		for idx, rp := range *op.ResponsibleParties {
			i.ResponsibleParties[idx] = *(&ResponsibleParty{}).UnmarshalOscal(rp)
		}
	}
	return i
}

func (i *Attestation) MarshalOscal() *oscalTypes_1_1_3.AttestationStatements {
	ret := &oscalTypes_1_1_3.AttestationStatements{}
	if len(i.Parts) > 0 {
		sub := make([]oscalTypes_1_1_3.AssessmentPart, len(i.Parts))
		for i, sp := range i.Parts {
			sub[i] = *sp.MarshalOscal()
		}
		ret.Parts = sub
	}
	if len(i.ResponsibleParties) > 0 {
		rps := make([]oscalTypes_1_1_3.ResponsibleParty, len(i.ResponsibleParties))
		for idx := range i.ResponsibleParties {
			rps[idx] = *i.ResponsibleParties[idx].MarshalOscal()
		}
		ret.ResponsibleParties = &rps
	}
	return ret
}

type TermsAndConditions struct {
	UUIDModel
	AssessmentPlanID uuid.UUID
	Parts            []AssessmentPart `gorm:"many2many:terms_and_conditions_parts"`
}

func (i *TermsAndConditions) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentPlanTermsAndConditions) *TermsAndConditions {
	*i = TermsAndConditions{}
	if op.Parts != nil {
		parts := ConvertList(op.Parts, func(data oscalTypes_1_1_3.AssessmentPart) AssessmentPart {
			output := AssessmentPart{}
			output.UnmarshalOscal(data)
			return output
		})
		i.Parts = parts
	}
	return i
}

func (i *TermsAndConditions) MarshalOscal() *oscalTypes_1_1_3.AssessmentPlanTermsAndConditions {
	ret := &oscalTypes_1_1_3.AssessmentPlanTermsAndConditions{}
	if len(i.Parts) > 0 {
		parts := make([]oscalTypes_1_1_3.AssessmentPart, len(i.Parts))
		for idx := range i.Parts {
			parts[idx] = *i.Parts[idx].MarshalOscal()
		}
		ret.Parts = &parts
	}
	return ret
}

type AssessmentPart struct {
	UUIDModel
	Name             string
	NS               string
	Class            string
	Title            string
	Prose            string
	Props            datatypes.JSONSlice[Prop]
	Links            datatypes.JSONSlice[Link]
	AssessmentPartID *uuid.UUID
	Parts            []AssessmentPart
}

func (p *AssessmentPart) UnmarshalOscal(data oscalTypes_1_1_3.AssessmentPart) *AssessmentPart {
	id, err := uuid.Parse(data.UUID)
	if err != nil {
		if data.UUID == "" {
			id = uuid.New()
		} else {
			panic(err)
		}
	}
	*p = AssessmentPart{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Name:  data.Name,
		NS:    data.Ns,
		Class: data.Class,
		Title: data.Title,
		Prose: data.Prose,
		Props: ConvertOscalToProps(data.Props),
		Links: ConvertOscalToLinks(data.Links),
		Parts: ConvertList(data.Parts, func(data oscalTypes_1_1_3.AssessmentPart) AssessmentPart {
			output := AssessmentPart{}
			output.UnmarshalOscal(data)
			return output
		}),
	}
	return p
}

func (p *AssessmentPart) MarshalOscal() *oscalTypes_1_1_3.AssessmentPart {
	op := &oscalTypes_1_1_3.AssessmentPart{
		UUID:  p.ID.String(),
		Name:  p.Name,
		Ns:    p.NS,
		Class: p.Class,
		Title: p.Title,
		Prose: p.Prose,
		//Props: ConvertPropsToOscal(p.Props),
		//Links: ConvertLinksToOscal(p.Links),
	}
	if len(p.Links) > 0 {
		op.Links = ConvertLinksToOscal(p.Links)
	}
	if len(p.Props) > 0 {
		op.Props = ConvertPropsToOscal(p.Props)
	}
	if len(p.Parts) > 0 {
		sub := make([]oscalTypes_1_1_3.AssessmentPart, len(p.Parts))
		for i, sp := range p.Parts {
			sub[i] = *sp.MarshalOscal()
		}
		op.Parts = &sub
	}
	return op
}

type LocalDefinitions struct {
	UUIDModel

	Remarks              *string
	Components           []SystemComponent `gorm:"many2many:local_definition_components"`
	InventoryItems       []InventoryItem   `gorm:"many2many:local_definition_inventory_items"`
	Users                []SystemUser      `gorm:"many2many:local_definition_users"`
	ObjectivesAndMethods []LocalObjective  `gorm:"many2many:local_definition_objectives"`
	Activities           []Activity        `gorm:"many2many:local_definition_activities"`

	ParentID   uuid.UUID
	ParentType string
}

func (i *LocalDefinitions) UnmarshalOscal(op oscalTypes_1_1_3.LocalDefinitions) *LocalDefinitions {
	*i = LocalDefinitions{
		Remarks: &op.Remarks,
	}
	// Components
	if op.Components != nil {
		i.Components = make([]SystemComponent, len(*op.Components))
		for idx, c := range *op.Components {
			i.Components[idx] = *(&SystemComponent{}).UnmarshalOscal(c)
		}
	}
	// InventoryItems
	if op.InventoryItems != nil {
		i.InventoryItems = make([]InventoryItem, len(*op.InventoryItems))
		for idx, it := range *op.InventoryItems {
			i.InventoryItems[idx] = *(&InventoryItem{}).UnmarshalOscal(it)
		}
	}
	// Users
	if op.Users != nil {
		i.Users = make([]SystemUser, len(*op.Users))
		for idx, u := range *op.Users {
			i.Users[idx] = *(&SystemUser{}).UnmarshalOscal(u)
		}
	}
	// ObjectivesAndMethods
	if op.ObjectivesAndMethods != nil {
		i.ObjectivesAndMethods = make([]LocalObjective, len(*op.ObjectivesAndMethods))
		for idx, lo := range *op.ObjectivesAndMethods {
			i.ObjectivesAndMethods[idx] = *(&LocalObjective{}).UnmarshalOscal(lo)
		}
	}
	// Activities
	if op.Activities != nil {
		i.Activities = make([]Activity, len(*op.Activities))
		for idx, a := range *op.Activities {
			i.Activities[idx] = *(&Activity{}).UnmarshalOscal(a)
		}
	}
	return i
}

func (i *LocalDefinitions) MarshalOscal() *oscalTypes_1_1_3.LocalDefinitions {
	// Handle nil LocalDefinitions
	if i == nil {
		return nil
	}

	ret := &oscalTypes_1_1_3.LocalDefinitions{}

	// Remarks - check for nil before dereferencing
	if i.Remarks != nil {
		ret.Remarks = *i.Remarks
	}
	if len(i.Components) > 0 {
		comps := make([]oscalTypes_1_1_3.SystemComponent, len(i.Components))
		for idx := range i.Components {
			comps[idx] = *i.Components[idx].MarshalOscal()
		}
		ret.Components = &comps
	}
	if len(i.InventoryItems) > 0 {
		items := make([]oscalTypes_1_1_3.InventoryItem, len(i.InventoryItems))
		for idx := range i.InventoryItems {
			items[idx] = i.InventoryItems[idx].MarshalOscal()
		}
		ret.InventoryItems = &items
	}
	if len(i.Users) > 0 {
		users := make([]oscalTypes_1_1_3.SystemUser, len(i.Users))
		for idx := range i.Users {
			users[idx] = *i.Users[idx].MarshalOscal()
		}
		ret.Users = &users
	}
	if len(i.ObjectivesAndMethods) > 0 {
		lo := make([]oscalTypes_1_1_3.LocalObjective, len(i.ObjectivesAndMethods))
		for idx := range i.ObjectivesAndMethods {
			lo[idx] = *i.ObjectivesAndMethods[idx].MarshalOscal()
		}
		ret.ObjectivesAndMethods = &lo
	}
	if len(i.Activities) > 0 {
		acts := make([]oscalTypes_1_1_3.Activity, len(i.Activities))
		for idx := range i.Activities {
			acts[idx] = *i.Activities[idx].MarshalOscal()
		}
		ret.Activities = &acts
	}
	return ret
}

type LocalObjective struct {
	UUIDModel

	ControlID string  // required
	Control   Control `gorm:"references:ID"`

	Description *string
	Remarks     *string
	Props       datatypes.JSONSlice[Prop]
	Links       datatypes.JSONSlice[Link]

	Parts datatypes.JSONSlice[Part] // required
}

func (i *LocalObjective) UnmarshalOscal(op oscalTypes_1_1_3.LocalObjective) *LocalObjective {
	*i = LocalObjective{
		ControlID: op.ControlId,
	}
	i.Description = &op.Description
	i.Remarks = &op.Remarks
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	if op.Parts != nil {
		parts := ConvertList(&op.Parts, func(data oscalTypes_1_1_3.Part) Part {
			output := Part{}
			output.UnmarshalOscal(data)
			return output
		})
		i.Parts = parts
	}
	return i
}

func (i *LocalObjective) MarshalOscal() *oscalTypes_1_1_3.LocalObjective {
	ret := &oscalTypes_1_1_3.LocalObjective{
		ControlId:   i.ControlID,
		Description: *i.Description,
		Remarks:     *i.Remarks,
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if len(i.Parts) > 0 {
		parts := make([]oscalTypes_1_1_3.Part, len(i.Parts))
		for i, sp := range i.Parts {
			parts[i] = *sp.MarshalOscal()
		}
		ret.Parts = parts
	}
	return ret
}

type ImportSsp oscalTypes_1_1_3.ImportSsp

func (i *ImportSsp) UnmarshalOscal(oip oscalTypes_1_1_3.ImportSsp) *ImportSsp {
	*i = ImportSsp(oip)
	return i
}

func (i *ImportSsp) MarshalOscal() *oscalTypes_1_1_3.ImportSsp {
	p := oscalTypes_1_1_3.ImportSsp(*i)
	return &p
}

type ImportAp oscalTypes_1_1_3.ImportAp

func (i *ImportAp) UnmarshalOscal(oip oscalTypes_1_1_3.ImportAp) *ImportAp {
	*i = ImportAp(oip)
	return i
}

func (i *ImportAp) MarshalOscal() *oscalTypes_1_1_3.ImportAp {
	p := oscalTypes_1_1_3.ImportAp(*i)
	return &p
}

// Task can fall under an AssessmentPlan, AssessmentResult, or Response
type Task struct {
	UUIDModel

	Type        string // required: [ milestone | action ]
	Title       string // required
	Description *string
	Remarks     *string
	Props       datatypes.JSONSlice[Prop] `json:"props"`
	Links       datatypes.JSONSlice[Link] `json:"links"`

	Dependencies         []TaskDependency // Different struct, as each dependency can have additional remarks
	Tasks                []Task           `gorm:"many2many:task_tasks"` // Sub tasks
	AssociatedActivities []AssociatedActivity
	Subjects             []AssessmentSubject `gorm:"many2many:task_subjects"`
	ResponsibleRole      []ResponsibleRole   `gorm:"polymorphic:Parent;"`
	Timing               *datatypes.JSONType[oscalTypes_1_1_3.EventTiming]

	ParentID   *uuid.UUID
	ParentType string
}

func (i *Task) UnmarshalOscal(op oscalTypes_1_1_3.Task) *Task {
	id := uuid.MustParse(op.UUID)
	*i = Task{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Type:        op.Type,
		Title:       op.Title,
		Description: &op.Description,
	}
	i.Remarks = &op.Remarks
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	// Dependencies
	if op.Dependencies != nil {
		i.Dependencies = make([]TaskDependency, len(*op.Dependencies))
		for idx, td := range *op.Dependencies {
			i.Dependencies[idx] = *(&TaskDependency{}).UnmarshalOscal(td)
		}
	}
	// Tasks (sub-tasks)
	if op.Tasks != nil {
		i.Tasks = make([]Task, len(*op.Tasks))
		for idx, st := range *op.Tasks {
			i.Tasks[idx] = *(&Task{}).UnmarshalOscal(st)
		}
	}
	// AssociatedActivities
	if op.AssociatedActivities != nil {
		i.AssociatedActivities = make([]AssociatedActivity, len(*op.AssociatedActivities))
		for idx, aa := range *op.AssociatedActivities {
			i.AssociatedActivities[idx] = *(&AssociatedActivity{}).UnmarshalOscal(aa)
		}
	}
	// Subjects
	if op.Subjects != nil {
		i.Subjects = make([]AssessmentSubject, len(*op.Subjects))
		for idx, s := range *op.Subjects {
			i.Subjects[idx] = *(&AssessmentSubject{}).UnmarshalOscal(s)
		}
	}
	// ResponsibleRole
	if op.ResponsibleRoles != nil {
		i.ResponsibleRole = make([]ResponsibleRole, len(*op.ResponsibleRoles))
		for idx, rr := range *op.ResponsibleRoles {
			i.ResponsibleRole[idx] = *(&ResponsibleRole{}).UnmarshalOscal(rr)
		}
	}
	// Timing
	if op.Timing != nil {
		timing := datatypes.NewJSONType(*op.Timing)
		i.Timing = &timing
	}
	return i
}

func (i *Task) MarshalOscal() *oscalTypes_1_1_3.Task {
	ret := &oscalTypes_1_1_3.Task{
		UUID:        i.ID.String(),
		Type:        i.Type,
		Title:       i.Title,
		Description: *i.Description,
	}
	ret.Remarks = *i.Remarks
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if len(i.Dependencies) > 0 {
		deps := make([]oscalTypes_1_1_3.TaskDependency, len(i.Dependencies))
		for idx := range i.Dependencies {
			deps[idx] = *i.Dependencies[idx].MarshalOscal()
		}
		ret.Dependencies = &deps
	}
	if len(i.Tasks) > 0 {
		tasks := make([]oscalTypes_1_1_3.Task, len(i.Tasks))
		for idx := range i.Tasks {
			tasks[idx] = *i.Tasks[idx].MarshalOscal()
		}
		ret.Tasks = &tasks
	}
	if len(i.AssociatedActivities) > 0 {
		aas := make([]oscalTypes_1_1_3.AssociatedActivity, len(i.AssociatedActivities))
		for idx := range i.AssociatedActivities {
			aas[idx] = *i.AssociatedActivities[idx].MarshalOscal()
		}
		ret.AssociatedActivities = &aas
	}
	if len(i.Subjects) > 0 {
		subjs := make([]oscalTypes_1_1_3.AssessmentSubject, len(i.Subjects))
		for idx := range i.Subjects {
			subjs[idx] = *i.Subjects[idx].MarshalOscal()
		}
		ret.Subjects = &subjs
	}
	if len(i.ResponsibleRole) > 0 {
		rrs := make([]oscalTypes_1_1_3.ResponsibleRole, len(i.ResponsibleRole))
		for idx := range i.ResponsibleRole {
			rrs[idx] = *i.ResponsibleRole[idx].MarshalOscal()
		}
		ret.ResponsibleRoles = &rrs
	}
	if i.Timing != nil {
		et := i.Timing.Data()
		ret.Timing = &et
	}
	return ret
}

type TaskDependency struct {
	UUIDModel
	TaskID  uuid.UUID
	Task    Task
	Remarks *string
}

func (i *TaskDependency) UnmarshalOscal(op oscalTypes_1_1_3.TaskDependency) *TaskDependency {
	*i = TaskDependency{
		TaskID:  uuid.MustParse(op.TaskUuid),
		Remarks: &op.Remarks,
	}
	return i
}

func (i *TaskDependency) MarshalOscal() *oscalTypes_1_1_3.TaskDependency {
	return &oscalTypes_1_1_3.TaskDependency{
		TaskUuid: i.TaskID.String(),
		Remarks:  *i.Remarks,
	}
}

type AssessmentAsset struct {
	UUIDModel

	Components          []SystemComponent    `gorm:"many2many:assessment_asset_components"`
	AssessmentPlatforms []AssessmentPlatform // required

	ParentType string
	ParentID   uuid.UUID
}

func (i *AssessmentAsset) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentAssets) *AssessmentAsset {
	id := uuid.New()
	*i = AssessmentAsset{
		UUIDModel: UUIDModel{
			ID: &id,
		},
	}
	// AssessmentPlatforms
	if op.AssessmentPlatforms != nil {
		i.AssessmentPlatforms = make([]AssessmentPlatform, len(op.AssessmentPlatforms))
		for idx, ap := range op.AssessmentPlatforms {
			i.AssessmentPlatforms[idx] = *(&AssessmentPlatform{}).UnmarshalOscal(ap)
		}
	}
	// Components
	if op.Components != nil {
		i.Components = make([]SystemComponent, len(*op.Components))
		for idx, c := range *op.Components {
			systemComponent := (&SystemComponent{}).UnmarshalOscal(c)
			systemComponent.ParentID = &id
			systemComponent.ParentType = "assessment_asset"
			i.Components[idx] = *systemComponent
		}
	}
	return i
}

func (i *AssessmentAsset) MarshalOscal() *oscalTypes_1_1_3.AssessmentAssets {
	ret := &oscalTypes_1_1_3.AssessmentAssets{}
	if len(i.AssessmentPlatforms) > 0 {
		aps := make([]oscalTypes_1_1_3.AssessmentPlatform, len(i.AssessmentPlatforms))
		for idx := range i.AssessmentPlatforms {
			aps[idx] = *i.AssessmentPlatforms[idx].MarshalOscal()
		}
		ret.AssessmentPlatforms = aps
	}
	// Include Components if they exist
	if len(i.Components) > 0 {
		components := make([]oscalTypes_1_1_3.SystemComponent, len(i.Components))
		for idx := range i.Components {
			components[idx] = *i.Components[idx].MarshalOscal()
		}
		ret.Components = &components
	}
	return ret
}

type AssessmentPlatform struct {
	UUIDModel
	AssessmentAssetID uuid.UUID
	AssessmentAsset   AssessmentAsset
	Title             *string
	Remarks           *string
	Props             datatypes.JSONSlice[Prop]
	Links             datatypes.JSONSlice[Link]
	UsesComponents    []UsesComponent
}

func (i *AssessmentPlatform) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentPlatform) *AssessmentPlatform {
	id := uuid.MustParse(op.UUID)
	*i = AssessmentPlatform{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Title:   &op.Title,
		Remarks: &op.Remarks,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	// UsesComponents
	if op.UsesComponents != nil {
		i.UsesComponents = make([]UsesComponent, len(*op.UsesComponents))
		for idx, uc := range *op.UsesComponents {
			i.UsesComponents[idx] = *(&UsesComponent{}).UnmarshalOscal(uc)
		}
	}
	return i
}

func (i *AssessmentPlatform) MarshalOscal() *oscalTypes_1_1_3.AssessmentPlatform {
	ret := &oscalTypes_1_1_3.AssessmentPlatform{
		UUID:    i.ID.String(),
		Title:   *i.Title,
		Remarks: *i.Remarks,
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if len(i.UsesComponents) > 0 {
		ucs := make([]oscalTypes_1_1_3.UsesComponent, len(i.UsesComponents))
		for idx := range i.UsesComponents {
			ucs[idx] = *i.UsesComponents[idx].MarshalOscal()
		}
		ret.UsesComponents = &ucs
	}
	return ret
}

type UsesComponent struct {
	UUIDModel
	AssessmentPlatformID uuid.UUID
	AssessmentPlatform   *AssessmentPlatform // parent
	Remarks              *string
	Props                datatypes.JSONSlice[Prop]
	Links                datatypes.JSONSlice[Link]
	ComponentID          uuid.UUID
	Component            DefinedComponent   // child
	ResponsibleParties   []ResponsibleParty `gorm:"many2many:uses_component_responsible_parties"`
}

func (i *UsesComponent) UnmarshalOscal(op oscalTypes_1_1_3.UsesComponent) *UsesComponent {
	*i = UsesComponent{
		ComponentID: uuid.MustParse(op.ComponentUuid),
		Remarks:     &op.Remarks,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	if op.ResponsibleParties != nil {
		i.ResponsibleParties = make([]ResponsibleParty, len(*op.ResponsibleParties))
		for idx, rp := range *op.ResponsibleParties {
			i.ResponsibleParties[idx] = *(&ResponsibleParty{}).UnmarshalOscal(rp)
		}
	}
	return i
}

func (i *UsesComponent) MarshalOscal() *oscalTypes_1_1_3.UsesComponent {
	ret := &oscalTypes_1_1_3.UsesComponent{
		ComponentUuid: i.ComponentID.String(),
		Remarks:       *i.Remarks,
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if len(i.ResponsibleParties) > 0 {
		rps := make([]oscalTypes_1_1_3.ResponsibleParty, len(i.ResponsibleParties))
		for idx := range i.ResponsibleParties {
			rps[idx] = *i.ResponsibleParties[idx].MarshalOscal()
		}
		ret.ResponsibleParties = &rps
	}
	return ret
}

type AssessmentSubject struct {
	// Assessment Subject is a loose reference to some subject.
	// A subject can be a Component, InventoryItem, Location, Party, User, Resource.
	// In our struct we don't store the type, but rather have relations to each of these, and when marhsalling and unmarshalling,
	// setting the type to what we know it is.
	UUIDModel

	// Type represents a component, party, location, user, or inventory item.
	// It will likely be updated once we can map it correctly
	Type        string
	Description *string
	Remarks     *string
	Props       datatypes.JSONSlice[Prop]
	Links       datatypes.JSONSlice[Link]

	IncludeAll      *datatypes.JSONType[*IncludeAll]
	IncludeSubjects []SelectSubjectById
	ExcludeSubjects []SelectSubjectById

	Evidence []Evidence `gorm:"many2many:evidence_subjects;"`
}

func (i *AssessmentSubject) UnmarshalOscal(op oscalTypes_1_1_3.AssessmentSubject) *AssessmentSubject {
	*i = AssessmentSubject{
		Description: &op.Description,
		Remarks:     &op.Remarks,
		Type:        op.Type,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	if op.IncludeAll != nil {
		ia := datatypes.NewJSONType(op.IncludeAll)
		i.IncludeAll = &ia
	}
	if op.IncludeSubjects != nil {
		i.IncludeSubjects = make([]SelectSubjectById, len(*op.IncludeSubjects))
		for idx, ss := range *op.IncludeSubjects {
			i.IncludeSubjects[idx] = *(&SelectSubjectById{}).UnmarshalOscal(ss)
		}
	}
	if op.ExcludeSubjects != nil {
		i.ExcludeSubjects = make([]SelectSubjectById, len(*op.ExcludeSubjects))
		for idx, ss := range *op.ExcludeSubjects {
			i.ExcludeSubjects[idx] = *(&SelectSubjectById{}).UnmarshalOscal(ss)
		}
	}
	return i
}

func (i *AssessmentSubject) MarshalOscal() *oscalTypes_1_1_3.AssessmentSubject {
	ret := &oscalTypes_1_1_3.AssessmentSubject{
		Type: i.Type,
	}
	if i.Description != nil {
		ret.Description = *i.Description
	}
	if i.Remarks != nil {
		ret.Remarks = *i.Remarks
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if i.IncludeAll != nil {
		ia := i.IncludeAll.Data()
		ret.IncludeAll = ia
	}
	if len(i.IncludeSubjects) > 0 {
		iss := make([]oscalTypes_1_1_3.SelectSubjectById, len(i.IncludeSubjects))
		for idx := range i.IncludeSubjects {
			iss[idx] = *i.IncludeSubjects[idx].MarshalOscal()
		}
		ret.IncludeSubjects = &iss
	}
	if len(i.ExcludeSubjects) > 0 {
		ess := make([]oscalTypes_1_1_3.SelectSubjectById, len(i.ExcludeSubjects))
		for idx := range i.ExcludeSubjects {
			ess[idx] = *i.ExcludeSubjects[idx].MarshalOscal()
		}
		ret.ExcludeSubjects = &ess
	}
	return ret
}

type SelectSubjectById struct {
	UUIDModel
	AssessmentSubjectID uuid.UUID

	// SubjectUUID technically represents a UUID of a component, party, location, user, or inventory item.
	// It will likely be updated once we can map it correctly
	SubjectUUID uuid.UUID
	Remarks     *string
	Props       datatypes.JSONSlice[Prop]
	Links       datatypes.JSONSlice[Link]
}

func (i *SelectSubjectById) UnmarshalOscal(op oscalTypes_1_1_3.SelectSubjectById) *SelectSubjectById {
	*i = SelectSubjectById{
		SubjectUUID: uuid.MustParse(op.SubjectUuid),
	}
	i.Remarks = &op.Remarks
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	return i
}

func (i *SelectSubjectById) MarshalOscal() *oscalTypes_1_1_3.SelectSubjectById {
	ret := &oscalTypes_1_1_3.SelectSubjectById{
		SubjectUuid: i.SubjectUUID.String(),
		Remarks:     *i.Remarks,
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	return ret
}

type AssociatedActivity struct {
	UUIDModel
	TaskID  uuid.UUID // Belongs to a task
	Remarks *string

	ActivityID       uuid.UUID
	Activity         Activity
	Props            datatypes.JSONSlice[Prop]
	Links            datatypes.JSONSlice[Link]
	ResponsibleRoles []ResponsibleRole   `gorm:"polymorphic:Parent;"`
	Subjects         []AssessmentSubject `gorm:"many2many:associated_activity_subjects"` // required
}

func (i *AssociatedActivity) UnmarshalOscal(op oscalTypes_1_1_3.AssociatedActivity) *AssociatedActivity {
	id := uuid.MustParse(op.ActivityUuid)
	*i = AssociatedActivity{
		Activity: Activity{
			UUIDModel: UUIDModel{
				ID: &id,
			},
		},
		Remarks: &op.Remarks,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	// ResponsibleRoles
	if op.ResponsibleRoles != nil {
		i.ResponsibleRoles = make([]ResponsibleRole, len(*op.ResponsibleRoles))
		for idx, rr := range *op.ResponsibleRoles {
			i.ResponsibleRoles[idx] = *(&ResponsibleRole{}).UnmarshalOscal(rr)
		}
	}
	// Subjects
	if op.Subjects != nil {
		i.Subjects = make([]AssessmentSubject, len(op.Subjects))
		for idx, s := range op.Subjects {
			i.Subjects[idx] = *(&AssessmentSubject{}).UnmarshalOscal(s)
		}
	}
	return i
}

func (i *AssociatedActivity) MarshalOscal() *oscalTypes_1_1_3.AssociatedActivity {
	ret := &oscalTypes_1_1_3.AssociatedActivity{
		ActivityUuid: i.Activity.ID.String(),
		Remarks:      *i.Remarks,
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if len(i.ResponsibleRoles) > 0 {
		rrs := make([]oscalTypes_1_1_3.ResponsibleRole, len(i.ResponsibleRoles))
		for idx := range i.ResponsibleRoles {
			rrs[idx] = *i.ResponsibleRoles[idx].MarshalOscal()
		}
		ret.ResponsibleRoles = &rrs
	}
	if len(i.Subjects) > 0 {
		subjs := make([]oscalTypes_1_1_3.AssessmentSubject, len(i.Subjects))
		for idx := range i.Subjects {
			subjs[idx] = *i.Subjects[idx].MarshalOscal()
		}
		ret.Subjects = subjs
	}
	return ret
}

type Activity struct {
	UUIDModel
	Title       *string `json:"title,omitempty"`
	Description string  `json:"description,omitempty"` // required
	Remarks     *string `json:"remarks,omitempty"`     // required

	Props datatypes.JSONSlice[Prop] `json:"props,omitempty"`
	Links datatypes.JSONSlice[Link] `json:"links,omitempty"`
	Steps []Step                    `json:"steps,omitempty"`

	RelatedControlsID *uuid.UUID
	RelatedControls   *ReviewedControls `json:"related-controls,omitempty"`
	ResponsibleRoles  []ResponsibleRole `gorm:"polymorphic:Parent" json:"responsible-roles,omitempty"`
}

func (i *Activity) UnmarshalOscal(op oscalTypes_1_1_3.Activity) *Activity {
	id := uuid.MustParse(op.UUID)
	*i = Activity{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Title:       &op.Title,
		Description: op.Description,
		Remarks:     &op.Remarks,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	// Steps
	if op.Steps != nil {
		i.Steps = make([]Step, len(*op.Steps))
		for idx, s := range *op.Steps {
			i.Steps[idx] = *(&Step{}).UnmarshalOscal(s)
		}
	}
	// RelatedControls
	if op.RelatedControls != nil {
		i.RelatedControls = (&ReviewedControls{}).UnmarshalOscal(*op.RelatedControls)
	}
	// ResponsibleRoles
	if op.ResponsibleRoles != nil {
		i.ResponsibleRoles = make([]ResponsibleRole, len(*op.ResponsibleRoles))
		for idx, rr := range *op.ResponsibleRoles {
			i.ResponsibleRoles[idx] = *(&ResponsibleRole{}).UnmarshalOscal(rr)
		}
	}
	return i
}

func (i *Activity) MarshalOscal() *oscalTypes_1_1_3.Activity {
	ret := &oscalTypes_1_1_3.Activity{
		UUID:        i.ID.String(),
		Description: i.Description,
	}
	if i.Title != nil {
		ret.Title = *i.Title
	}
	if i.Remarks != nil {
		ret.Remarks = *i.Remarks
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if len(i.Steps) > 0 {
		steps := make([]oscalTypes_1_1_3.Step, len(i.Steps))
		for idx := range i.Steps {
			steps[idx] = *i.Steps[idx].MarshalOscal()
		}
		ret.Steps = &steps
	}

	if i.RelatedControls != nil {
		rc := i.RelatedControls.MarshalOscal()
		ret.RelatedControls = rc
	}
	if len(i.ResponsibleRoles) > 0 {
		rrs := make([]oscalTypes_1_1_3.ResponsibleRole, len(i.ResponsibleRoles))
		for idx := range i.ResponsibleRoles {
			rrs[idx] = *i.ResponsibleRoles[idx].MarshalOscal()
		}
		ret.ResponsibleRoles = &rrs
	}
	return ret
}

type Step struct {
	UUIDModel
	ActivityID uuid.UUID

	Title       *string `json:"title,omitempty"`
	Description string  `json:"description,omitempty"` // required
	Remarks     *string `json:"remarks,omitempty"`

	Props datatypes.JSONSlice[Prop] `json:"props,omitempty"`
	Links datatypes.JSONSlice[Link] `json:"links,omitempty"`

	ResponsibleRoles []ResponsibleRole `gorm:"polymorphic:Parent;" json:"responsible-roles,omitempty"`

	ReviewedControlsID *uuid.UUID
	ReviewedControls   *ReviewedControls `json:"reviewed-controls,omitempty"`
}

func (i *Step) UnmarshalOscal(op oscalTypes_1_1_3.Step) *Step {
	id := uuid.MustParse(op.UUID)
	*i = Step{
		UUIDModel: UUIDModel{
			ID: &id,
		},
		Title:       &op.Title,
		Description: op.Description,
		Remarks:     &op.Remarks,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	// ResponsibleRoles
	if op.ResponsibleRoles != nil {
		i.ResponsibleRoles = make([]ResponsibleRole, len(*op.ResponsibleRoles))
		for idx, rr := range *op.ResponsibleRoles {
			i.ResponsibleRoles[idx] = *(&ResponsibleRole{}).UnmarshalOscal(rr)
		}
	}
	// ReviewedControls
	if op.ReviewedControls != nil {
		i.ReviewedControls = (&ReviewedControls{}).UnmarshalOscal(*op.ReviewedControls)
	}
	return i
}

func (i *Step) MarshalOscal() *oscalTypes_1_1_3.Step {
	ret := &oscalTypes_1_1_3.Step{
		UUID:        i.ID.String(),
		Description: i.Description,
	}
	if i.Remarks != nil {
		ret.Remarks = *i.Remarks
	}
	if i.Title != nil {
		ret.Title = *i.Title
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if len(i.ResponsibleRoles) > 0 {
		rrs := make([]oscalTypes_1_1_3.ResponsibleRole, len(i.ResponsibleRoles))
		for idx := range i.ResponsibleRoles {
			rrs[idx] = *i.ResponsibleRoles[idx].MarshalOscal()
		}
		ret.ResponsibleRoles = &rrs
	}
	if i.ReviewedControls != nil {
		ret.ReviewedControls = i.ReviewedControls.MarshalOscal()
	}
	return ret
}

type ReviewedControls struct {
	UUIDModel
	Description                *string
	Remarks                    *string
	Props                      datatypes.JSONSlice[Prop]
	Links                      datatypes.JSONSlice[Link]
	ControlSelections          []ControlSelection // required
	ControlObjectiveSelections []ControlObjectiveSelection
}

func (i *ReviewedControls) UnmarshalOscal(op oscalTypes_1_1_3.ReviewedControls) *ReviewedControls {
	*i = ReviewedControls{
		Description: &op.Description,
		Remarks:     &op.Remarks,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	// ControlSelections
	if op.ControlSelections != nil {
		i.ControlSelections = make([]ControlSelection, len(op.ControlSelections))
		for idx, cs := range op.ControlSelections {
			i.ControlSelections[idx] = *(&ControlSelection{}).UnmarshalOscal(cs)
		}
	}
	// ControlObjectiveSelections
	if op.ControlObjectiveSelections != nil {
		i.ControlObjectiveSelections = make([]ControlObjectiveSelection, len(*op.ControlObjectiveSelections))
		for idx, cos := range *op.ControlObjectiveSelections {
			i.ControlObjectiveSelections[idx] = *(&ControlObjectiveSelection{}).UnmarshalOscal(cos)
		}
	}
	return i
}

func (i *ReviewedControls) MarshalOscal() *oscalTypes_1_1_3.ReviewedControls {
	ret := &oscalTypes_1_1_3.ReviewedControls{}
	if i.Description != nil {
		ret.Description = *i.Description
	}
	if i.Remarks != nil {
		ret.Remarks = *i.Remarks
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if len(i.ControlSelections) > 0 {
		css := make([]oscalTypes_1_1_3.AssessedControls, len(i.ControlSelections))
		for idx := range i.ControlSelections {
			css[idx] = *i.ControlSelections[idx].MarshalOscal()
		}
		ret.ControlSelections = css
	}
	if len(i.ControlObjectiveSelections) > 0 {
		coss := make([]oscalTypes_1_1_3.ReferencedControlObjectives, len(i.ControlObjectiveSelections))
		for idx := range i.ControlObjectiveSelections {
			coss[idx] = *i.ControlObjectiveSelections[idx].MarshalOscal()
		}
		ret.ControlObjectiveSelections = &coss
	}
	return ret
}

type ControlSelection struct {
	UUIDModel
	ReviewedControlsID uuid.UUID
	Description        *string
	Remarks            *string
	Props              datatypes.JSONSlice[Prop]
	Links              datatypes.JSONSlice[Link]

	IncludeAll      *datatypes.JSONType[IncludeAll]
	IncludeControls []AssessedControlsSelectControlById `gorm:"many2many:control_selection_assessed_controls_included"`
	ExcludeControls []AssessedControlsSelectControlById `gorm:"many2many:control_selection_assessed_controls_excluded"`
}

func (i *ControlSelection) UnmarshalOscal(op oscalTypes_1_1_3.AssessedControls) *ControlSelection {
	*i = ControlSelection{
		Description: &op.Description,
		Remarks:     &op.Remarks,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	if op.IncludeAll != nil {
		ia := datatypes.NewJSONType(*op.IncludeAll)
		i.IncludeAll = &ia
	}
	if op.IncludeControls != nil {
		i.IncludeControls = make([]AssessedControlsSelectControlById, len(*op.IncludeControls))
		for idx, sc := range *op.IncludeControls {
			i.IncludeControls[idx] = *(&AssessedControlsSelectControlById{}).UnmarshalOscal(sc)
		}
	}
	if op.ExcludeControls != nil {
		i.ExcludeControls = make([]AssessedControlsSelectControlById, len(*op.ExcludeControls))
		for idx, sc := range *op.ExcludeControls {
			i.ExcludeControls[idx] = *(&AssessedControlsSelectControlById{}).UnmarshalOscal(sc)
		}
	}
	return i
}

func (i *ControlSelection) MarshalOscal() *oscalTypes_1_1_3.AssessedControls {
	ret := &oscalTypes_1_1_3.AssessedControls{
		Description: *i.Description,
		Remarks:     *i.Remarks,
	}
	if len(i.Props) > 0 {
		ret.Props = ConvertPropsToOscal(i.Props)
	}
	if len(i.Links) > 0 {
		ret.Links = ConvertLinksToOscal(i.Links)
	}
	if i.IncludeAll != nil {
		includeAll := i.IncludeAll.Data()
		ret.IncludeAll = &includeAll
	}
	if len(i.IncludeControls) > 0 {
		incs := make([]oscalTypes_1_1_3.AssessedControlsSelectControlById, len(i.IncludeControls))
		for idx := range i.IncludeControls {
			incs[idx] = i.IncludeControls[idx].MarshalOscal()
		}
		ret.IncludeControls = &incs
	}
	if len(i.ExcludeControls) > 0 {
		excs := make([]oscalTypes_1_1_3.AssessedControlsSelectControlById, len(i.ExcludeControls))
		for idx := range i.ExcludeControls {
			excs[idx] = i.ExcludeControls[idx].MarshalOscal()
		}
		ret.ExcludeControls = &excs
	}
	return ret
}

type ControlObjectiveSelection struct {
	UUIDModel
	ReviewedControlsID uuid.UUID

	Description *string
	Remarks     *string
	Props       datatypes.JSONSlice[Prop]
	Links       datatypes.JSONSlice[Link]

	IncludeAll        *datatypes.JSONType[IncludeAll]
	IncludeObjectives []SelectObjectiveById `gorm:"Polymorphic:Parent;polymorphicValue:included"`
	ExcludeObjectives []SelectObjectiveById `gorm:"Polymorphic:Parent;polymorphicValue:excluded"`
}

func (i *ControlObjectiveSelection) UnmarshalOscal(op oscalTypes_1_1_3.ReferencedControlObjectives) *ControlObjectiveSelection {
	*i = ControlObjectiveSelection{
		Description: &op.Description,
		Remarks:     &op.Remarks,
	}
	if op.Props != nil {
		i.Props = ConvertOscalToProps(op.Props)
	}
	if op.Links != nil {
		i.Links = ConvertOscalToLinks(op.Links)
	}
	if op.IncludeAll != nil {
		includeAll := datatypes.NewJSONType(*op.IncludeAll)
		i.IncludeAll = &includeAll
	}
	if op.IncludeObjectives != nil {
		i.IncludeObjectives = make([]SelectObjectiveById, len(*op.IncludeObjectives))
		for idx, so := range *op.IncludeObjectives {
			i.IncludeObjectives[idx] = *(&SelectObjectiveById{}).UnmarshalOscal(so)
		}
	}
	if op.ExcludeObjectives != nil {
		i.ExcludeObjectives = make([]SelectObjectiveById, len(*op.ExcludeObjectives))
		for idx, so := range *op.ExcludeObjectives {
			i.ExcludeObjectives[idx] = *(&SelectObjectiveById{}).UnmarshalOscal(so)
		}
	}
	return i
}

func (i *ControlObjectiveSelection) MarshalOscal() *oscalTypes_1_1_3.ReferencedControlObjectives {
	ret := &oscalTypes_1_1_3.ReferencedControlObjectives{
		Description: *i.Description,
		Remarks:     *i.Remarks,
		Props:       ConvertPropsToOscal(i.Props),
		Links:       ConvertLinksToOscal(i.Links),
	}
	if i.IncludeAll != nil {
		includeAll := i.IncludeAll.Data()
		ret.IncludeAll = &includeAll
	}
	if len(i.IncludeObjectives) > 0 {
		ios := make([]oscalTypes_1_1_3.SelectObjectiveById, len(i.IncludeObjectives))
		for idx := range i.IncludeObjectives {
			ios[idx] = *i.IncludeObjectives[idx].MarshalOscal()
		}
		ret.IncludeObjectives = &ios
	}
	if len(i.ExcludeObjectives) > 0 {
		eos := make([]oscalTypes_1_1_3.SelectObjectiveById, len(i.ExcludeObjectives))
		for idx := range i.ExcludeObjectives {
			eos[idx] = *i.ExcludeObjectives[idx].MarshalOscal()
		}
		ret.ExcludeObjectives = &eos
	}
	return ret
}

type SelectObjectiveById struct { // We should figure out what this looks like for real, because this references objectives hidden in `part`s of a control
	UUIDModel
	Objective string // required

	ParentID   uuid.UUID
	ParentType string
}

func (i *SelectObjectiveById) UnmarshalOscal(op oscalTypes_1_1_3.SelectObjectiveById) *SelectObjectiveById {
	*i = SelectObjectiveById{
		Objective: op.ObjectiveId,
	}
	return i
}

func (i *SelectObjectiveById) MarshalOscal() *oscalTypes_1_1_3.SelectObjectiveById {
	return &oscalTypes_1_1_3.SelectObjectiveById{
		ObjectiveId: i.Objective,
	}
}

type AssessedControlsSelectControlById struct {
	UUIDModel
	ControlID  string
	Control    Control     `gorm:"references:ID"`
	Statements []Statement `gorm:"many2many:assessed_controls_select_control_by_id_statements;"`
}

func (s *AssessedControlsSelectControlById) UnmarshalOscal(o oscalTypes_1_1_3.AssessedControlsSelectControlById) *AssessedControlsSelectControlById {
	statements := []Statement{}
	if o.StatementIds != nil {
		for _, statement := range *o.StatementIds {
			statements = append(statements, Statement{
				StatementId: statement,
			})
		}
	}
	*s = AssessedControlsSelectControlById{
		ControlID:  o.ControlId,
		Statements: statements,
	}

	return s
}

func (s *AssessedControlsSelectControlById) MarshalOscal() oscalTypes_1_1_3.AssessedControlsSelectControlById {
	controls := oscalTypes_1_1_3.AssessedControlsSelectControlById{
		ControlId: s.ControlID,
	}
	if len(s.Statements) > 0 {
		statementIDs := []string{}
		for _, statement := range s.Statements {
			statementIDs = append(statementIDs, statement.StatementId)
		}
		controls.StatementIds = &statementIDs
	}
	return controls
}
