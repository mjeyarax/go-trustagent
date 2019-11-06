module intel/isecl/go-trust-agent

require (
	github.com/go-delve/delve v1.3.2 // indirect
	github.com/google/uuid v1.1.1
	github.com/gorilla/context v1.1.1
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20190219172222-a4c6cb3142f2
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	gopkg.in/yaml.v2 v2.2.2
	intel/isecl/lib/common v1.0.0-Beta
	intel/isecl/lib/tpmprovider v1.0.0-Beta
)

replace intel/isecl/lib/common => github.com/intel-secl/common v1.0.0-Beta.0.20190920051932-22c16ec493a3

replace intel/isecl/lib/tpmprovider => gitlab.devtools.intel.com/sst/isecl/lib/tpm-provider.git v0.0.0-20191031175459-2f621858eb7d
