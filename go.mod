module intel/isecl/go-trust-agent/v2

require (
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/jinzhu/gorm v1.9.11
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	gopkg.in/yaml.v2 v2.2.2
	intel-secl v0.0.0
	intel/isecl/lib/clients/v2 v2.1.0
	intel/isecl/lib/common/v2 v2.1.0
	intel/isecl/lib/platform-info/v2 v2.1.0
	intel/isecl/lib/tpmprovider/v2 v2.1.0
)

replace intel/isecl/lib/common/v2 => github.com/intel-secl/common/v2 v2.1.0

replace intel/isecl/lib/tpmprovider/v2 => github.com/intel-secl/tpm-provider/v2 v2.1.0

replace intel/isecl/lib/platform-info/v2 => github.com/intel-secl/platform-info/v2 v2.1.0

replace intel/isecl/lib/clients/v2 => github.com/intel-secl/clients/v2 v2.1.0

replace intel-secl => ../intel-secl/
