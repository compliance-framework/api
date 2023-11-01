package handler

// idResponse is a struct that holds the ID of a model.
// swagger:model
type idResponse struct {
	// The unique identifier of the plan.
	// Required: true
	// Example: "456def"
	Id string `json:"id"`
}

// catalogIdResponse is a struct that holds the ID of a catalog.
// swagger:model
type catalogIdResponse struct {
	// The unique identifier of the catalog.
	// Required: true
	// Example: "123abc"
	Id string `json:"id"`
}