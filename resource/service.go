/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"context"
	"crypto/tls"
	"fmt"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/auth"
	commContext "intel/isecl/lib/common/context"
	"intel/isecl/lib/common/log/message"
	"intel/isecl/lib/common/middleware"
	ct "intel/isecl/lib/common/types/aas"
	"intel/isecl/lib/tpmprovider"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	
	commLog "intel/isecl/lib/common/log"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

const (
	getAIKPerm             = "aik:retrieve"
	getAIKCAPerm           = "aik_ca:retrieve"
	getBindingKeyPerm      = "binding_key:retrieve"
	getDAAPerm             = "daa:retrieve"
	getHostInfoPerm        = "host_info:retrieve"
	postDeployManifestPerm = "deploy_manifest:create"
	postAppMeasurementPerm = "application_measurement:create"
	postDeployTagPerm      = "deploy_tag:create"
	postQuotePerm          = "quote:create"
)

type TrustAgentService struct {
	port   int
	router *mux.Router
}

type endpointError struct {
	Message    string
	StatusCode int
}

type privilegeError struct {
	StatusCode int
	Message    string
}

func (e privilegeError) Error() string {
	log.Trace("resource/resource:Error() Entering")
	defer log.Trace("resource/resource:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func (e endpointError) Error() string {
	log.Trace("resource/resource:Error() Entering")
	defer log.Trace("resource/resource:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

var cacheTime, _ = time.ParseDuration(constants.JWTCertsCacheTime)
var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

//To be implemented if JWT certificate is needed from any other services
func fnGetJwtCerts() error {
	log.Trace("server:fnGetJwtCerts() Entering")
	defer log.Trace("server:fnGetJwtCerts() Leaving")
	return nil
}

func CreateTrustAgentService(config *config.TrustAgentConfiguration, tpmFactory tpmprovider.TpmFactory) (*TrustAgentService, error) {

	if config.TrustAgentService.Port == 0 {
		return nil, errors.New("Port cannot be zero")
	}

	trustAgentService := TrustAgentService{
		port: config.TrustAgentService.Port,
	}

	// Register routes...
	trustAgentService.router = mux.NewRouter()
	trustAgentService.router.Use(middleware.NewTokenAuth(constants.TrustedJWTSigningCertsDir, constants.TrustedCaCertsDir, fnGetJwtCerts, cacheTime))

	// these can be enabled on the basis of the decision regarding whether role name or permission name should be checked in JWT
	/*
		// use permission-based access control for webservices
		trustAgentService.router.HandleFunc("/v2/aik", errorHandler(requiresPermission(getAik(), []string{getAIKPerm}))).Methods("GET")
		trustAgentService.router.HandleFunc("/v2/host", errorHandler(requiresPermission(getPlatformInfo(), []string{getHostInfoPerm}))).Methods("GET")
		trustAgentService.router.HandleFunc("/v2/tpm/quote", errorHandler(requiresPermission(getTpmQuote(config, tpmFactory), []string{postQuotePerm}))).Methods("POST")
		trustAgentService.router.HandleFunc("/v2/binding-key-certificate", errorHandler(requiresPermission(getBindingKeyCertificate(), []string{getBindingKeyPerm}))).Methods("GET")
		trustAgentService.router.HandleFunc("/v2/tag", errorHandler(requiresPermission(setAssetTag(config, tpmFactory), []string{postDeployTagPerm}))).Methods("POST")
		trustAgentService.router.HandleFunc("/v2/host/application-measurement", errorHandler(requiresPermission(getApplicationMeasurement(), []string{postAppMeasurementPerm}))).Methods("POST")
		trustAgentService.router.HandleFunc("/v2/deploy/manifest", errorHandler(requiresPermission(deployManifest(), []string{postDeployManifestPerm}))).Methods("POST")
	*/

	// use rolename-based access control for webservices
	trustAgentService.router.HandleFunc("/v2/aik", errorHandler(requiresRole(getAik(), []string{constants.AdministratorGroup}))).Methods("GET")
	trustAgentService.router.HandleFunc("/v2/host", errorHandler(requiresRole(getPlatformInfo(), []string{constants.AdministratorGroup}))).Methods("GET")
	trustAgentService.router.HandleFunc("/v2/tpm/quote", errorHandler(requiresRole(getTpmQuote(config, tpmFactory), []string{constants.AdministratorGroup}))).Methods("POST")
	trustAgentService.router.HandleFunc("/v2/binding-key-certificate", errorHandler(requiresRole(getBindingKeyCertificate(), []string{constants.AdministratorGroup}))).Methods("GET")
	trustAgentService.router.HandleFunc("/v2/tag", errorHandler(requiresRole(setAssetTag(config, tpmFactory), []string{constants.AdministratorGroup}))).Methods("POST")
	trustAgentService.router.HandleFunc("/v2/host/application-measurement", errorHandler(requiresRole(getApplicationMeasurement(), []string{constants.AdministratorGroup}))).Methods("POST")
	trustAgentService.router.HandleFunc("/v2/deploy/manifest", errorHandler(requiresRole(deployManifest(), []string{constants.AdministratorGroup}))).Methods("POST")

	return &trustAgentService, nil
}

func (service *TrustAgentService) Start() error {
	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(log.StandardLogger().Writer(), "", 0)
	h := &http.Server{
		Addr:      fmt.Sprintf(":%d", service.port),
		Handler:   handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(os.Stderr, service.router)),
		ErrorLog:  httpLog,
		TLSConfig: tlsconfig,
	}

	// dispatch web server go routine
	go func() {
		if err := h.ListenAndServeTLS(constants.TLSCertFilePath, constants.TLSKeyFilePath); err != nil {
			log.WithError(err).Info("Failed to start trustagent server")
			stop <- syscall.SIGTERM
		}
	}()

	log.Infof("TrustAgent service is running: %d", service.port)

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		log.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	return nil
}

/*
// requiresPermission - ensures that correct permission is present in JWT
// this requires lib/common to be sourced from
// replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v1.0/task/roles-and-permissions
func requiresPermission(eh endpointHandler, permissionNames []string) endpointHandler {
	log.Trace("resource/resource:requiresPermission() Entering")
	defer log.Trace("resource/resource:requiresPermission() Leaving")
	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := commContext.GetUserPermissions(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Could not get user roles from http context"))
			secLog.Errorf("resource/resource:requiresPermission() %s Roles: %v | Context: %v", message.AuthenticationFailed, permissionNames, r.Context())
			return errors.Wrap(err, "resource/resource:requiresPermission() Could not get user roles from http context")
		}
		reqPermissions := ct.PermissionInfo{Service: constants.AASServiceName, Rules: permissionNames}

		_, foundMatchingPermission := auth.ValidatePermissionAndGetRoleContext(privileges, reqPermissions,
			true)
		if !foundMatchingPermission {
			w.WriteHeader(http.StatusUnauthorized)
			secLog.Error(message.UnauthorizedAccess)
			secLog.Errorf("resource/resource:requiresPermission() %s Insufficient privileges to access %s", message.UnauthorizedAccess, r.RequestURI)
			return &privilegeError{Message: "Insufficient privileges to access " + r.RequestURI, StatusCode: http.StatusUnauthorized}
		}
		secLog.Infof("resource/resource:requiresPermission() %s - %s", message.AuthorizedAccess, r.RequestURI)
		return eh(w, r)
	}
}
*/

// this requires lib/common to be sourced from
// replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v2.0/develop
// requiresPermission - ensures that correct rolename is present in JWT
func requiresRole(eh endpointHandler, roleNames []string) endpointHandler {
	log.Trace("resource/resource:requiresPermission() Entering")
	defer log.Trace("resource/resource:requiresPermission() Leaving")
	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := commContext.GetUserRoles(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Could not get user roles from http context"))
			secLog.Errorf("resource/resource:requiresPermission() %s Roles: %v | Context: %v", message.AuthenticationFailed, roleNames, r.Context())
			return errors.Wrap(err, "resource/resource:requiresPermission() Could not get user roles from http context")
		}
		reqRoles := make([]ct.RoleInfo, len(roleNames))
		for i, role := range roleNames {
			reqRoles[i] = ct.RoleInfo{Service: constants.AASServiceName, Name: role}
		}

		secLog.Debugf("resource/resource:requiresPermission() Req Roles: %v", reqRoles)
		_, foundRole := auth.ValidatePermissionAndGetRoleContext(privileges, reqRoles,
			true)
		if !foundRole {
			w.WriteHeader(http.StatusUnauthorized)
			secLog.Error(message.UnauthorizedAccess)
			secLog.Errorf("resource/resource:requiresPermission() %s Insufficient privileges to access %s", message.UnauthorizedAccess, r.RequestURI)
			return &privilegeError{Message: "Insufficient privileges to access " + r.RequestURI, StatusCode: http.StatusUnauthorized}
		}
		secLog.Infof("resource/resource:requiresPermission() %s - %s", message.AuthorizedAccess, r.RequestURI)
		return eh(w, r)
	}
}

// endpointHandler is the same as http.ResponseHandler, but returns an error that can be handled by a generic
// middleware handler
type endpointHandler func(w http.ResponseWriter, r *http.Request) error

func errorHandler(eh endpointHandler) http.HandlerFunc {
	log.Trace("resource/resource:errorHandler() Entering")
	defer log.Trace("resource/resource:errorHandler() Leaving")
	return func(w http.ResponseWriter, r *http.Request) {
		if err := eh(w, r); err != nil {
			if gorm.IsRecordNotFoundError(err) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			switch t := err.(type) {
			case *endpointError:
				http.Error(w, t.Message, t.StatusCode)
			case privilegeError:
				http.Error(w, t.Message, t.StatusCode)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	}
}
