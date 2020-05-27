module intel/isecl/go-trust-agent/v2

require (
	cloud.google.com/go v0.37.4 // indirect
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/intel-secl/intel-secl/v3 v3.0.0-00010101000000-000000000000
	github.com/jinzhu/gorm v1.9.12
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v2 v2.2.2
	intel/isecl/lib/clients/v2 v2.1.0
	intel/isecl/lib/common/v2 v2.1.0
	intel/isecl/lib/platform-info/v2 v2.1.0
	intel/isecl/lib/tpmprovider/v2 v2.1.0
)

replace intel/isecl/lib/common/v2 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v2 v2.2/develop

replace intel/isecl/lib/tpmprovider/v2 => gitlab.devtools.intel.com/sst/isecl/lib/tpm-provider.git/v2 v2.2/develop

replace intel/isecl/lib/platform-info/v2 => gitlab.devtools.intel.com/sst/isecl/lib/platform-info.git/v2 v2.2/develop

replace intel/isecl/lib/clients/v2 => gitlab.devtools.intel.com/sst/isecl/lib/clients.git/v2 v2.2/develop

replace github.com/intel-secl/intel-secl/v3 => gitlab.devtools.intel.com/sst/isecl/intel-secl.git/v3 v3.0/tasks/certify-sk-bk-keys

