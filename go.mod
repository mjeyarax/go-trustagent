module intel/isecl/go-trust-agent/v3

require (
	github.com/form3tech-oss/jwt-go v3.2.2+incompatible // indirect
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/intel-secl/intel-secl/v3 v3.4.0
	github.com/jinzhu/gorm v1.9.15
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.6.1
	gopkg.in/yaml.v2 v2.3.0
	intel/isecl/lib/common/v3 v3.4.0
	intel/isecl/lib/platform-info/v3 v3.4.0
	intel/isecl/lib/tpmprovider/v3 v3.4.0
)

replace (
	github.com/intel-secl/intel-secl/v3 => gitlab.devtools.intel.com/sst/isecl/intel-secl.git/v3 v3.4/develop
	github.com/vmware/govmomi => github.com/arijit8972/govmomi fix-tpm-attestation-output
	intel/isecl/lib/common/v3 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v3 v3.4/develop
	intel/isecl/lib/platform-info/v3 => gitlab.devtools.intel.com/sst/isecl/lib/platform-info.git/v3 v3.4/develop
	intel/isecl/lib/tpmprovider/v3 => gitlab.devtools.intel.com/sst/isecl/lib/tpm-provider.git/v3 v3.4/develop
)

