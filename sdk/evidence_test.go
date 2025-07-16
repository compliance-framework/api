//go:build integration

package sdk_test

import (
	"context"
	"fmt"
	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

func TestEvidenceSDK(t *testing.T) {
	suite.Run(t, new(EvidenceSDKIntegrationSuite))
}

type EvidenceSDKIntegrationSuite struct {
	IntegrationBaseTestSuite
}

func (suite *EvidenceSDKIntegrationSuite) TestCreate() {
	suite.Run("Evidence can be created through the SDK", func() {
		client := suite.GetSDKTestClient()
		fmt.Println(client)
		// Create two catalogs with the same group ID structure
		evidence := types.Evidence{
			UUID:    uuid.New(),
			Title:   "Some piece of evidence",
			Start:   time.Now().Add(-time.Hour),
			End:     time.Now().Add(-time.Hour).Add(time.Minute),
			Expires: internal.Pointer(time.Now().Add(30 * 24 * time.Hour)),
			Labels: map[string]string{
				"provider": "aws",
				"service":  "EC2",
				"instance": "i-12345",
			},
			Activities: []types.Activity{
				{
					UUID:  uuid.New(),
					Title: "Collect evidence",
					Steps: []types.Step{
						{
							UUID:  uuid.New(),
							Title: "Run CLI to collect configuration",
						},
						{
							UUID:  uuid.New(),
							Title: "Convert to JSON object",
						},
					},
				},
				{
					UUID:  uuid.New(),
					Title: "Evaluate compliance to policies",
					Steps: []types.Step{
						{
							UUID:  uuid.New(),
							Title: "Pass JSON configuration into policy engine",
						},
						{
							UUID:  uuid.New(),
							Title: "Evaluate policy and generate results",
						},
					},
				},
			},
			InventoryItems: []types.InventoryItem{
				{
					Identifier: "web-server/ec2/i-12345",
					Type:       "web-server",
					Title:      "EC2 Instance - i-12345",
					Props:      nil,
					Links:      nil,
					ImplementedComponents: []types.ComponentIdentifier{
						{
							Identifier: "components/common/ssh",
						},
						{
							Identifier: "components/common/ubuntu-22",
						},
					},
				},
			},
			Components: []types.Component{
				{
					Identifier:  "components/common/ssh",
					Type:        "software",
					Title:       "Secure Shell (SSH)",
					Description: "SSH is used to manage remote access to virtual and hardware servers.",
					Purpose:     "",
					Protocols: []types.Protocol{
						{
							UUID:  uuid.MustParse("3480C9EC-BC6B-4851-B248-BA78D83ECECE"),
							Title: "SSH",
							Name:  "SSH",
							PortRanges: &[]types.PortRange{
								{
									End:       22,
									Start:     22,
									Transport: "TCP",
								},
							},
						},
					},
				},
				{
					Identifier:  "components/common/ubuntu-22.04",
					Type:        "operating-system",
					Title:       "Ubuntu Server v22.04",
					Description: "Ubuntu is a free, open-source Linux distribution maintained by Canonical that pairs a user-friendly desktop and server experience with regular, predictable releases. It comes with extensive repositories, strong security defaults, and long-term support options that make it popular for personal use, cloud deployments, and enterprise environments.",
				},
				{
					Identifier:  "components/common/aws/ec2",
					Type:        "service",
					Title:       "Amazon Elastic Compute Cloud (EC2)",
					Description: "Amazon Elastic Compute Cloud (EC2) is a web service that lets you quickly provision resizable virtual servers in AWS’s global cloud, paying only for the compute you use. It offers a choice of instance types, networking and storage options, and automation features that allow everything from burst-scale web apps to enterprise workloads to run securely and on demand.",
				},
			},
			Subjects: []types.Subject{
				{
					Identifier: "web-server/ec2/i-12345",
					Type:       "inventory-item",
				},
				{
					Identifier: "components/common/ssh",
					Type:       "component",
				},
				{
					Identifier: "components/common/aws/ec2",
					Type:       "component",
				},
			},
			Status: types.ObjectiveStatus{
				Reason:  "fail", // "pass" | "fail" | "other"
				Remarks: "Policy evaluation failed as password authentication is enabled. SSH password authentication should be disabled.",
				State:   "not-satisfied", // "satisfied" | "not-satisfied"
			},
		}
		err := client.Evidence.Create(context.TODO(), evidence)
		suite.NoError(err)
	})
}
