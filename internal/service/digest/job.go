package digest

import (
	"context"

	"go.uber.org/zap"
)

// GlobalDigestJob is a scheduled job that sends global evidence digests
type GlobalDigestJob struct {
	service *Service
	logger  *zap.SugaredLogger
}

// NewGlobalDigestJob creates a new global digest job
func NewGlobalDigestJob(service *Service, logger *zap.SugaredLogger) *GlobalDigestJob {
	return &GlobalDigestJob{
		service: service,
		logger:  logger,
	}
}

// Name returns the unique name of the job
func (j *GlobalDigestJob) Name() string {
	return "global-evidence-digest"
}

// Execute runs the digest job
func (j *GlobalDigestJob) Execute(ctx context.Context) error {
	j.logger.Debug("Executing global evidence digest job")
	return j.service.SendGlobalDigest(ctx)
}
