package internal

func Pointer[K any](value K) *K {
	return &value
}
