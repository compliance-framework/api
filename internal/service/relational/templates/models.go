package templates

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type RiskTemplate struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	PluginID       string  `json:"pluginId" gorm:"type:text;not null;index"`
	PolicyPackage  string  `json:"policyPackage" gorm:"type:text;not null;index"`
	Name           string  `json:"name" gorm:"type:text;not null"`
	Title          string  `json:"title" gorm:"type:text;not null"`
	Statement      string  `json:"statement" gorm:"type:text;not null"`
	LikelihoodHint *string `json:"likelihoodHint" gorm:"type:varchar(32)"`
	ImpactHint     *string `json:"impactHint" gorm:"type:varchar(32)"`

	RemediationTemplateID *uuid.UUID           `json:"remediationTemplateId" gorm:"type:uuid;index"`
	RemediationTemplate   *RemediationTemplate `json:"remediationTemplate,omitempty" gorm:"foreignKey:RemediationTemplateID;references:ID"`

	ViolationIDs datatypes.JSONSlice[string] `json:"violationIds" gorm:"type:jsonb"`
	IsActive     bool                        `json:"isActive" gorm:"not null;default:true;index"`

	ThreatRefs []RiskTemplateThreatRef `json:"threatRefs,omitempty" gorm:"foreignKey:RiskTemplateID;constraint:OnDelete:CASCADE"`
}

func (RiskTemplate) TableName() string {
	return "risk_templates"
}

type RiskTemplateThreatRef struct {
	relational.UUIDModel
	RiskTemplateID uuid.UUID `json:"riskTemplateId" gorm:"type:uuid;not null;index"`

	System     string  `json:"system" gorm:"type:text;not null"`
	ExternalID string  `json:"externalId" gorm:"column:external_id;type:text;not null"`
	Title      string  `json:"title" gorm:"type:text;not null"`
	URL        *string `json:"url" gorm:"type:text"`
}

func (RiskTemplateThreatRef) TableName() string {
	return "risk_template_threat_refs"
}

type RemediationTemplate struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Title       string  `json:"title" gorm:"type:text;not null"`
	Description *string `json:"description" gorm:"type:text"`

	Tasks []RemediationTask `json:"tasks,omitempty" gorm:"foreignKey:RemediationTemplateID;constraint:OnDelete:CASCADE"`
}

func (RemediationTemplate) TableName() string {
	return "remediation_templates"
}

type RemediationTask struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	RemediationTemplateID uuid.UUID `json:"remediationTemplateId" gorm:"type:uuid;not null;index"`
	Title                 string    `json:"title" gorm:"type:text;not null"`
	OrderIndex            int       `json:"orderIndex" gorm:"not null"`
}

func (RemediationTask) TableName() string {
	return "remediation_tasks"
}
