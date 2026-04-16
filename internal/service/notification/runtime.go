package notification

type Runtime struct {
	registry *Registry
	resolver *Resolver
	service  *Service
}

func NewRuntime(
	transport Transport,
	users UserRepository,
	configuredDestinations ConfiguredDestinationResolver,
	opts ...ServiceOption,
) (*Runtime, error) {
	registry, err := NewRegistry()
	if err != nil {
		return nil, err
	}

	var providers ProviderLookup
	if lookup, ok := transport.(ProviderLookup); ok {
		providers = lookup
	}

	resolver := NewResolver(users, configuredDestinations, providers)

	return &Runtime{
		registry: registry,
		resolver: resolver,
		service:  NewService(transport, registry, resolver, opts...),
	}, nil
}

func MustNewRuntime(
	transport Transport,
	users UserRepository,
	configuredDestinations ConfiguredDestinationResolver,
	opts ...ServiceOption,
) *Runtime {
	runtime, err := NewRuntime(transport, users, configuredDestinations, opts...)
	if err != nil {
		panic(err)
	}

	return runtime
}

func (r *Runtime) Register(definitions ...Definition) error {
	if r == nil || r.registry == nil {
		return ErrRegistryNotConfigured
	}

	for i := range definitions {
		if err := r.registry.Register(definitions[i]); err != nil {
			return err
		}
	}

	return nil
}

func (r *Runtime) MustRegister(definitions ...Definition) {
	if err := r.Register(definitions...); err != nil {
		panic(err)
	}
}

func (r *Runtime) Service() *Service {
	if r == nil {
		return nil
	}

	return r.service
}

func (r *Runtime) Registry() *Registry {
	if r == nil {
		return nil
	}

	return r.registry
}

func (r *Runtime) Resolver() *Resolver {
	if r == nil {
		return nil
	}

	return r.resolver
}
