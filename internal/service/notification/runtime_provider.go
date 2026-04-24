package notification

// RuntimeProvider builds scoped runtime factories from shared runtime composition.
// The configured destination resolver can vary by caller while the provider keeps
// transport and default service options centralized at bootstrap.
type RuntimeProvider interface {
	NewRuntimeFactory(configuredDestinations ConfiguredDestinationResolver) *RuntimeFactory
}

type staticRuntimeProvider struct {
	transport      Transport
	serviceOptions []ServiceOption
}

// NewStaticRuntimeProvider returns a RuntimeProvider backed by a fixed transport
// and service options. Callers provide configured-destination resolution per scope.
func NewStaticRuntimeProvider(transport Transport, opts ...ServiceOption) RuntimeProvider {
	return &staticRuntimeProvider{
		transport:      transport,
		serviceOptions: append([]ServiceOption(nil), opts...),
	}
}

func (p *staticRuntimeProvider) NewRuntimeFactory(configuredDestinations ConfiguredDestinationResolver) *RuntimeFactory {
	if p == nil {
		return NewRuntimeFactory(nil, configuredDestinations)
	}

	return NewRuntimeFactory(p.transport, configuredDestinations, p.serviceOptions...)
}
