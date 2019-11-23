module intel/isecl/go-trust-agent

require (
	github.com/go-delve/delve v1.3.2 // indirect
	github.com/google/uuid v1.1.1
	github.com/gorilla/context v1.1.1
	github.com/gorilla/handlers v1.4.0
	github.com/gorilla/mux v1.7.3
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	gopkg.in/yaml.v2 v2.2.2
	intel/isecl/lib/common v1.0.0-Beta
	intel/isecl/lib/tpmprovider v1.0.0-Beta
)

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v1.6-beta

replace intel/isecl/lib/tpmprovider => gitlab.devtools.intel.com/sst/isecl/lib/tpm-provider.git v1.0/go-trust-agent