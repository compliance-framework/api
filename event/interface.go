package event

type Subscriber[T any] func(string) (chan T, error)
type Publisher[T any] func(T, string) error
