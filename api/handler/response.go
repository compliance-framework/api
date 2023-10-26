package handler

// catalogIdResponse is a struct that holds the ID of a catalog.
// swagger:model
type catalogIdResponse struct {
	// The unique identifier of the catalog.
	// Required: true
	// Example: "123abc"
	Id string `json:"id"`
}

// planIdResponse is a struct that holds the ID of a plan.
// swagger:model
type planIdResponse struct {
	// The unique identifier of the plan.
	// Required: true
	// Example: "456def"
	Id string `json:"id"`
}

type profileIdResponse struct {
	Id string `json:"id"`
}
