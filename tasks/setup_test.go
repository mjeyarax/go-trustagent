
package tasks


import (
	"testing"

	"github.com/stretchr/testify/assert"

	"intel/isecl/go-trust-agent/config"
	"intel/isecl/lib/common/crypt"
)

func TestTakeOwnership(t *testing.T) {
	assert := assert.New(t)

	secretKey, err := crypt.GetRandomBytes(20)
	assert.NoError(err)

	cfg := config.TrustAgentConfiguration {}
	cfg.Tpm.SecretKey = secretKey

	registry, err := CreateTaskRegistry(&cfg, nil)
	assert.NoError(err)

	registry.RunCommand(TakeOwnershipCommand)

}