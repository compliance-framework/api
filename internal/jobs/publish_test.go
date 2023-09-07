package jobs

import (
	"fmt"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnect(t *testing.T) {
	testCases := []struct {
		name      string
		connErr   error
		encErr    error
		bindErr   error
		expectErr string
	}{
		{
			name: "success",
		},
		{
			name:      "fail connect",
			connErr:   fmt.Errorf("boom!"),
			expectErr: "boom!",
		},
		{
			name:      "fail encoding",
			encErr:    fmt.Errorf("boom!"),
			expectErr: "boom!",
		},
	}
	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := PublishJob{driver: &internal{
				ConnectFn: func(url string, options ...nats.Option) (*nats.Conn, error) {
					c := nats.Conn{}
					return &c, testCases[i].connErr
				},
				NewEncodedFn: func(c *nats.Conn, enc string) (*nats.EncodedConn, error) {
					return &nats.EncodedConn{}, testCases[i].encErr
				},
			},
			}
			err := p.Init()
			require.NoError(t, err)
			err = p.Connect("nats://nats:4222")
			if testCases[i].expectErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, testCases[i].expectErr)
			}
		})
	}

}
