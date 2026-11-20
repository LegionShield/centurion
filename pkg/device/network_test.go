package device

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAutoGetDevices(t *testing.T) {
	if testing.Short() {
		t.Skip("requires raw socket / NIC access")
	}
	ether, err := AutoGetDevices([]string{"1.1.1.1"})
	assert.NoError(t, err)
	PrintDeviceInfo(ether)
}
