package notification

// TargetConfigurator extends a delivery provider with target parsing,
// normalization, and display helpers used by admin/system configuration flows.
type TargetConfigurator interface {
	BuildTarget(rawTarget string) (Target, error)
	NormalizeTarget(target Target) (Target, error)
	DisplayTarget(target Target) (string, error)
}

func LookupTargetConfigurator(lookup ProviderLookup, providerID string) (TargetConfigurator, bool) {
	if lookup == nil {
		return nil, false
	}

	provider, ok := lookup.Provider(providerID)
	if !ok || provider == nil {
		return nil, false
	}

	configurator, ok := provider.(TargetConfigurator)
	return configurator, ok
}
