package sdk_test

import (
	"github.com/compliance-framework/api/sdk"
	"reflect"
	"testing"
)

func TestSeededUUID(t *testing.T) {
	t.Run("Consistent Seed", func(t *testing.T) {
		seedData := map[string]string{
			"plugin":   "local-ssh:v1.3.0",
			"policy":   "local-ssh:v1.3.0",
			"hostname": "k8s-worker-3",
		}

		uuid1, err := sdk.SeededUUID(seedData)
		if err != nil {
			t.Errorf("Failed to create UUID from dataset: %v", err)
		}

		uuid2, err := sdk.SeededUUID(seedData)
		if err != nil {
			t.Errorf("Failed to create UUID from dataset: %v", err)
		}

		if !reflect.DeepEqual(uuid1, uuid2) {
			t.Errorf("SeededUUID generated different UUIDs for the same seed")
		}
	})

	t.Run("Inconsistent Seed", func(t *testing.T) {
		uuid1, err := sdk.SeededUUID(map[string]string{
			"plugin": "local-ssh:v1.3.0",
		})
		if err != nil {
			t.Errorf("Failed to create UUID from dataset: %v", err)
		}

		uuid2, err := sdk.SeededUUID(map[string]string{
			"plugin": "local-ssh:v1.3.1",
		})
		if err != nil {
			t.Errorf("Failed to create UUID from dataset: %v", err)
		}

		if reflect.DeepEqual(uuid1, uuid2) {
			t.Errorf("SeededUUID generated the same UUID for different seeds")
		}
	})
}
