package config

// WorkerConfig contains configuration for background workers
// Environment variables:
//   - CCF_WORKER_ENABLED: Enable/disable workers (default: true)
//   - CCF_WORKER_COUNT: Number of concurrent workers (default: 5)
//   - CCF_WORKER_QUEUE: Queue name to process (default: "email")
//   - CCF_WORKER_USE_POLLING: Use River polling instead of PostgreSQL LISTEN/NOTIFY (default: false)
type WorkerConfig struct {
	// Enabled determines if workers should be started
	Enabled bool `mapstructure:"enabled"`

	// Number of worker goroutines to run
	Workers int `mapstructure:"workers"`

	// Queue is the name of the queue to work on
	Queue string `mapstructure:"queue"`

	// UsePolling makes River poll for jobs instead of using PostgreSQL LISTEN/NOTIFY.
	UsePolling bool `mapstructure:"use_polling"`

	// RetryPolicy defines how jobs should be retried
	RetryPolicy RetryPolicyConfig `mapstructure:"retry_policy"`
}

// RetryPolicyConfig defines retry behavior for jobs
type RetryPolicyConfig struct {
	// MaxAttempts is the maximum number of attempts for a job
	MaxAttempts int `mapstructure:"max_attempts"`
}

// DefaultWorkerConfig returns a default worker configuration
func DefaultWorkerConfig() *WorkerConfig {
	return &WorkerConfig{
		Enabled:    true,
		Workers:    5,
		Queue:      "email", // Default to email queue to match job configuration
		UsePolling: false,
		RetryPolicy: RetryPolicyConfig{
			MaxAttempts: 5,
		},
	}
}
