package relational

import (
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type BackMatter struct {
	UUIDModel
	ParentID   *string
	ParentType *string
	Resources  []BackMatterResource
}

func (b *BackMatter) UnmarshalOscal(resource oscaltypes113.BackMatter) *BackMatter {
	*b = BackMatter{
		Resources: ConvertList(resource.Resources, func(res oscaltypes113.Resource) BackMatterResource {
			bm := BackMatterResource{}
			bm.UnmarshalOscal(res)
			return bm
		}),
	}
	return b
}

// MarshalOscal converts the BackMatter back to an OSCAL BackMatter
func (b *BackMatter) MarshalOscal() *oscaltypes113.BackMatter {
	bm := &oscaltypes113.BackMatter{}
	// Always set resources to an empty array, even if no resources exist
	resources := make([]oscaltypes113.Resource, len(b.Resources))
	for i, r := range b.Resources {
		resources[i] = *r.MarshalOscal()
	}
	bm.Resources = &resources
	return bm
}

type BackMatterResource struct {
	ID           uuid.UUID                         `gorm:"primary_key"` // required
	BackMatterID uuid.UUID                         `gorm:"primary_key"`
	Title        *string                           `json:"title"`
	Description  *string                           `json:"description"`
	Remarks      *string                           `json:"remarks"`
	Citation     *datatypes.JSONType[Citation]     `json:"citation"`
	Base64       *datatypes.JSONType[Base64]       `json:"base64"`
	Props        datatypes.JSONSlice[Prop]         `json:"props"`
	DocumentIDs  datatypes.JSONSlice[DocumentID]   `json:"document-ids"`
	RLinks       datatypes.JSONSlice[ResourceLink] `json:"rlinks"`
}

func (c *BackMatterResource) UnmarshalOscal(resource oscaltypes113.Resource) *BackMatterResource {
	id := uuid.MustParse(resource.UUID)

	*c = BackMatterResource{
		ID:          id,
		Title:       &resource.Title,
		Description: &resource.Description,
		Remarks:     &resource.Remarks,

		Props: ConvertList(resource.Props, func(property oscaltypes113.Property) Prop {
			prop := Prop{}
			prop.UnmarshalOscal(property)
			return prop
		}),
		DocumentIDs: ConvertList(resource.DocumentIds, func(doc oscaltypes113.DocumentId) DocumentID {
			d := DocumentID{}
			d.UnmarshalOscal(doc)
			return d
		}),
		RLinks: ConvertList(resource.Rlinks, func(olink oscaltypes113.ResourceLink) ResourceLink {
			r := ResourceLink{}
			r.UnmarshalOscal(olink)
			return r
		}),
	}

	if resource.Citation != nil {
		citation := Citation{}
		citation.UnmarshalOscal(*resource.Citation)
		jcitation := datatypes.NewJSONType(citation)
		c.Citation = &jcitation
	}

	if resource.Base64 != nil {
		base64 := Base64{}
		base64.UnmarshalOscal(*resource.Base64)
		jbase64 := datatypes.NewJSONType(base64)
		c.Base64 = &jbase64
	}

	return c
}

// MarshalOscal converts the BackMatterResource back to an OSCAL Resource
func (b *BackMatterResource) MarshalOscal() *oscaltypes113.Resource {
	res := &oscaltypes113.Resource{
		UUID: b.ID.String(),
	}

	if b.Title != nil {
		res.Title = *b.Title
	}

	if b.Description != nil {
		res.Description = *b.Description
	}

	if b.Remarks != nil {
		res.Remarks = *b.Remarks
	}

	if len(b.Props) > 0 {
		props := *ConvertPropsToOscal(b.Props)
		res.Props = &props
	}
	if len(b.DocumentIDs) > 0 {
		docs := make([]oscaltypes113.DocumentId, len(b.DocumentIDs))
		for i, d := range b.DocumentIDs {
			docs[i] = oscaltypes113.DocumentId{
				Scheme:     string(d.Scheme),
				Identifier: d.Identifier,
			}
		}
		res.DocumentIds = &docs
	}
	if len(b.RLinks) > 0 {
		rls := make([]oscaltypes113.ResourceLink, len(b.RLinks))
		for i, rl := range b.RLinks {
			rls[i] = *rl.MarshalOscal()
		}
		res.Rlinks = &rls
	}
	if b.Citation != nil {
		citationData := b.Citation.Data()
		res.Citation = citationData.MarshalOscal()
	}
	if b.Base64 != nil {
		base64Data := b.Base64.Data()
		res.Base64 = base64Data.MarshalOscal()
	}
	return res
}

type Citation struct {
	Text  string `json:"text"` // required
	Props []Prop `json:"props"`
	Links []Link `json:"links"`
}

func (c *Citation) UnmarshalOscal(cit oscaltypes113.Citation) *Citation {
	*c = Citation{
		Text: cit.Text,
		Props: ConvertList(cit.Props, func(property oscaltypes113.Property) Prop {
			prop := Prop{}
			prop.UnmarshalOscal(property)
			return prop
		}),
		Links: ConvertList(cit.Links, func(olink oscaltypes113.Link) Link {
			link := Link{}
			link.UnmarshalOscal(olink)
			return link
		}),
	}
	return c
}

// MarshalOscal converts the Citation back to an OSCAL Citation
func (c *Citation) MarshalOscal() *oscaltypes113.Citation {
	cc := &oscaltypes113.Citation{
		Text: c.Text,
	}
	if len(c.Props) > 0 {
		props := make([]oscaltypes113.Property, len(c.Props))
		for i, p := range c.Props {
			props[i] = oscaltypes113.Property(p)
		}
		cc.Props = &props
	}
	if len(c.Links) > 0 {
		links := make([]oscaltypes113.Link, len(c.Links))
		for i, l := range c.Links {
			links[i] = oscaltypes113.Link(l)
		}
		cc.Links = &links
	}
	return cc
}

type HashAlgorithm string

const (
	HashAlgorithmSHA_224  HashAlgorithm = "SHA-224"
	HashAlgorithmSHA_256  HashAlgorithm = "SHA-256"
	HashAlgorithmSHA_384  HashAlgorithm = "SHA-384"
	HashAlgorithmSHA_512  HashAlgorithm = "SHA-512"
	HashAlgorithmSHA3_224 HashAlgorithm = "SHA3-224"
	HashAlgorithmSHA3_256 HashAlgorithm = "SHA3-256"
	HashAlgorithmSHA3_384 HashAlgorithm = "SHA3-384"
	HashAlgorithmSHA3_512 HashAlgorithm = "SHA3-512"
)

type Hash struct {
	Algorithm HashAlgorithm `json:"algorithm"` // required
	Value     string        `json:"value"`     // required
}

func (h *Hash) UnmarshalOscal(hash oscaltypes113.Hash) *Hash {
	*h = Hash{
		Algorithm: HashAlgorithm(hash.Algorithm),
		Value:     hash.Value,
	}
	return h
}

// MarshalOscal converts the Hash back to an OSCAL Hash
func (h *Hash) MarshalOscal() *oscaltypes113.Hash {
	return &oscaltypes113.Hash{
		Algorithm: string(h.Algorithm),
		Value:     h.Value,
	}
}

type ResourceLink struct {
	Href      string `json:"href"` // required
	MediaType string `json:"media-type"`
	Hashes    []Hash `json:"hashes"`
}

func (r *ResourceLink) UnmarshalOscal(orlink oscaltypes113.ResourceLink) {
	*r = ResourceLink{
		Href:      orlink.Href,
		MediaType: orlink.MediaType,
		Hashes: ConvertList(orlink.Hashes, func(ohash oscaltypes113.Hash) Hash {
			hash := Hash{}
			hash.UnmarshalOscal(ohash)
			return hash
		}),
	}
}

// MarshalOscal converts the ResourceLink back to an OSCAL ResourceLink
func (r *ResourceLink) MarshalOscal() *oscaltypes113.ResourceLink {
	rl := &oscaltypes113.ResourceLink{
		Href:      r.Href,
		MediaType: r.MediaType,
	}
	if len(r.Hashes) > 0 {
		hashes := make([]oscaltypes113.Hash, len(r.Hashes))
		for i, h := range r.Hashes {
			hashes[i] = *h.MarshalOscal()
		}
		rl.Hashes = &hashes
	}
	return rl
}

type Base64 struct {
	Filename  string `json:"filename"`
	MediaType string `json:"media-type"`
	Value     string `json:"value"` // required
}

func (b *Base64) UnmarshalOscal(base oscaltypes113.Base64) *Base64 {
	*b = Base64{
		Filename:  base.Filename,
		MediaType: base.MediaType,
		Value:     base.Value,
	}
	return b
}

// MarshalOscal converts the Base64 back to an OSCAL Base64
func (b *Base64) MarshalOscal() *oscaltypes113.Base64 {
	return &oscaltypes113.Base64{
		Filename:  b.Filename,
		MediaType: b.MediaType,
		Value:     b.Value,
	}
}
