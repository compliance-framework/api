package sdk

import (
	"fmt"
	"github.com/google/uuid"
	"hash/crc64"
	"math/rand"
	"slices"
	"strings"
)

// SeededUUID generates a consistent UUID for the same seedMap. This is useful for generating consistent StreamIDs across executions.
func SeededUUID(seedMap map[string]string) (uuid.UUID, error) {
	seedData := make([]string, 0)
	for k, v := range seedMap {
		seedData = append(seedData, fmt.Sprintf("%s=%s", k, v))
	}
	slices.Sort(seedData)
	seedSum := crc64.Checksum([]byte(strings.Join(seedData, "-")), crc64.MakeTable(crc64.ISO))
	random := rand.New(rand.NewSource(int64(seedSum)))
	return uuid.NewRandomFromReader(random)
}
