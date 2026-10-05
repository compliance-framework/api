//go:build integration

package templates_test

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/suite"
)

type SubjectTemplateResolverIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestSubjectTemplateResolverIntegration(t *testing.T) {
	suite.Run(t, new(SubjectTemplateResolverIntegrationSuite))
}

func (s *SubjectTemplateResolverIntegrationSuite) SetupTest() {
	s.Require().NoError(s.Migrator.Refresh())
}

func orgTemplate(plugin string) templaterel.SubjectTemplatePayload {
	title := "GitHub Organization: {{ .organization }}"
	return templaterel.SubjectTemplatePayload{
		Name:              "GitHub Organization",
		Type:              "component",
		SourceMode:        "runtime-derived",
		TitleTemplate:     &title,
		IdentityLabelKeys: []string{"organization"},
		Links:             []relational.Link{{Href: "https://github.com/{{ .organization }}", Rel: "canonical"}},
		SelectorLabels:    []templaterel.SubjectTemplateSelectorLabelInput{{Key: "_plugin", Value: plugin}},
		LabelSchema: []templaterel.SubjectTemplateLabelSchemaFieldInput{
			{Key: "_plugin"},
			{Key: "organization"},
			{Key: "env"},
		},
	}
}

func (s *SubjectTemplateResolverIntegrationSuite) TestUpsertsDefinedComponentPerPlugin() {
	svc := templaterel.NewSubjectTemplateService(s.DB)

	payload := orgTemplate("github")
	template, err := svc.Create(payload)
	s.Require().NoError(err)
	_, err = svc.Create(orgTemplate("github-enterprise"))
	s.Require().NoError(err)

	labels := []relational.Labels{
		{Name: "_plugin", Value: "github"},
		{Name: "organization", Value: "acme"},
		{Name: "env", Value: "prod"},
	}
	first, err := svc.ResolveOrUpsertComponentDefinition(templaterel.ResolveOrUpsertComponentDefinitionInput{EvidenceLabels: labels})
	s.Require().NoError(err)
	s.Require().Len(first.Subjects, 1)
	s.Equal("GitHub Organization: acme", first.Subjects[0].Title)

	// Resolving again takes the fast path and leaves the row as it is.
	again, err := svc.ResolveOrUpsertComponentDefinition(templaterel.ResolveOrUpsertComponentDefinitionInput{EvidenceLabels: labels})
	s.Require().NoError(err)
	s.Equal(first.DefinedComponentIDs, again.DefinedComponentIDs)

	// Template changes reach the existing DefinedComponent.
	software := "software"
	payload.ComponentType = &software
	_, err = svc.Update(*template.ID, payload)
	s.Require().NoError(err)
	updated, err := svc.ResolveOrUpsertComponentDefinition(templaterel.ResolveOrUpsertComponentDefinitionInput{EvidenceLabels: labels})
	s.Require().NoError(err)
	s.Equal(first.DefinedComponentIDs, updated.DefinedComponentIDs)

	var dc relational.DefinedComponent
	s.Require().NoError(s.DB.First(&dc, "id = ?", first.DefinedComponentIDs[0]).Error)
	s.Equal("software", dc.Type)
	s.Equal("GitHub Organization: acme", dc.Title)
	s.Require().Len(dc.Links, 1)
	s.Equal("https://github.com/acme", dc.Links[0].Href)
	s.Contains([]relational.Prop(dc.Props), relational.Prop{Ns: relational.CCFOSCALNamespace, Name: "identity", Class: "organization", Value: "acme"})
	s.Contains([]relational.Prop(dc.Props), relational.Prop{Ns: relational.CCFOSCALNamespace, Name: "label", Class: "env", Value: "prod"})

	// The same identity from another plugin gets its own DefinedComponent.
	other, err := svc.ResolveOrUpsertComponentDefinition(templaterel.ResolveOrUpsertComponentDefinitionInput{
		EvidenceLabels: []relational.Labels{
			{Name: "_plugin", Value: "github-enterprise"},
			{Name: "organization", Value: "acme"},
		},
	})
	s.Require().NoError(err)
	s.Require().Len(other.DefinedComponentIDs, 1)
	s.NotEqual(first.DefinedComponentIDs[0], other.DefinedComponentIDs[0])

	var identities int64
	s.Require().NoError(s.DB.Model(&templaterel.ComponentDefinitionIdentity{}).Count(&identities).Error)
	s.Equal(int64(2), identities)
}
