/*
Package oscal - This package contains the OSCAL model objects along with control plane structures.

Notes:

- If a model has a Uuid field defined, it signifies that it can be stored as a standalone object and can be reused by other model.

- If a property has a []Uuid type parameter, it indicates that this property will hold the Ids of other model objects.
*/
package domain
