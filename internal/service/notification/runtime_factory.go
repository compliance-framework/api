package notification

type RuntimeFactory struct {
	transport              Transport
	configuredDestinations ConfiguredDestinationResolver
	serviceOptions         []ServiceOption
}

func NewRuntimeFactory(
	transport Transport,
	configuredDestinations ConfiguredDestinationResolver,
	opts ...ServiceOption,
) *RuntimeFactory {
	return &RuntimeFactory{
		transport:              transport,
		configuredDestinations: configuredDestinations,
		serviceOptions:         append([]ServiceOption(nil), opts...),
	}
}

func (f *RuntimeFactory) NewRuntime(users UserRepository, definitions ...Definition) (*Runtime, error) {
	if f == nil {
		return nil, ErrTransportNotConfigured
	}

	runtime, err := NewRuntime(f.transport, users, f.configuredDestinations, f.serviceOptions...)
	if err != nil {
		return nil, err
	}

	if err := runtime.Register(definitions...); err != nil {
		return nil, err
	}

	return runtime, nil
}

func (f *RuntimeFactory) MustNewRuntime(users UserRepository, definitions ...Definition) *Runtime {
	runtime, err := f.NewRuntime(users, definitions...)
	if err != nil {
		panic(err)
	}

	return runtime
}

func (f *RuntimeFactory) NewService(users UserRepository, definitions ...Definition) (*Service, error) {
	runtime, err := f.NewRuntime(users, definitions...)
	if err != nil {
		return nil, err
	}

	return runtime.Service(), nil
}

func (f *RuntimeFactory) MustNewService(users UserRepository, definitions ...Definition) *Service {
	runtime := f.MustNewRuntime(users, definitions...)
	return runtime.Service()
}
