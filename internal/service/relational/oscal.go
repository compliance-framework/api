package relational

func ConvertList[in any, out any](list *[]in, mutate func(in) out) []out {
	if list == nil {
		return nil
	}
	output := make([]out, 0)
	for _, i := range *list {
		output = append(output, mutate(i))
	}
	return output
}
