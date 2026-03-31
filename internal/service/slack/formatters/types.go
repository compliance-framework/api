package formatters

type DigestSummaryEvidence struct {
	Title       string
	Description string
	ExpiresAt   string
	ID          string
}

type DigestSummary struct {
	TotalCount        int64
	SatisfiedCount    int64
	NotSatisfiedCount int64
	ExpiredCount      int64

	TopExpired      []DigestSummaryEvidence
	TopNotSatisfied []DigestSummaryEvidence

	BaseURL string
}
