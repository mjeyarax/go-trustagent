module intel/isecl/go-trust-agent/v2

require (
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.11
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	github.com/vmware/govmomi v0.22.2
	golang.org/x/crypto v0.0.0-20190325154230-a5d413f7728c
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	gopkg.in/yaml.v2 v2.3.0
	intel/isecl/lib/clients/v2 v2.2.0
	intel/isecl/lib/common/v2 v2.2.0
	intel/isecl/lib/platform-info/v2 v2.2.0
	intel/isecl/lib/tpmprovider/v2 v2.2.0
)

replace intel/isecl/lib/common/v2 => github.com/intel-secl/common/v2 v2.2.0

replace intel/isecl/lib/tpmprovider/v2 => github.com/intel-secl/tpm-provider/v2 v2.2.0

replace intel/isecl/lib/platform-info/v2 => github.com/intel-secl/platform-info/v2 v2.2.0

replace intel/isecl/lib/clients/v2 => gitlab.devtools.intel.com/sst/isecl/lib/clients.git/v2 v2.2.0

replace github.com/intel-secl/intel-secl/v3 => gitlab.devtools.intel.com/sst/isecl/intel-secl.git/v3 v3.0/feature/go-hvs

replace github.com/vmware/govmomi => github.com/arijit8972/govmomi fix-tpm-attestation-output
