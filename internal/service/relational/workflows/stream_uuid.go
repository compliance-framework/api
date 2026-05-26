package workflows

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

// ComputeExecutionStreamUUID derives the deterministic evidence stream UUID for a workflow
// execution. The same seed algorithm is used by EvidenceIntegration so both sides always
// agree on the UUID without a database round-trip.
func ComputeExecutionStreamUUID(definitionID, instanceID, executionID uuid.UUID) (uuid.UUID, error) {
	seed := fmt.Sprintf("execution:%s:%s:%s:%s",
		definitionID.String(),
		instanceID.String(),
		executionID.String(),
		"v1",
	)
	hash := sha256.Sum256([]byte(seed))
	h := hex.EncodeToString(hash[:16])
	return uuid.Parse(h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32])
}
