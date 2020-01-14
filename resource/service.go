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
	
	"github.com/gorilla/handlers"
	"github.com/sirupsen/logrus"
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
	log.Trace("resource/service:Error() Entering")
	defer log.Trace("resource/service:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func (e endpointError) Error() string {
	log.Trace("resource/service:Error() Entering")
	defer log.Trace("resource/service:Error() Leaving")
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

var cacheTime, _ = time.ParseDuration(constants.JWTCertsCacheTime)

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

	// use permission-based access control for webservices
	trustAgentService.router.HandleFunc("/v2/aik", errorHandler(requiresPermission(getAik(), []string{getAIKPerm}))).Methods("GET")
	trustAgentService.router.HandleFunc("/v2/host", errorHandler(requiresPermission(getPlatformInfo(), []string{getHostInfoPerm}))).Methods("GET")
	trustAgentService.router.HandleFunc("/v2/tpm/quote", errorHandler(requiresPermission(getTpmQuote(config, tpmFactory), []string{postQuotePerm}))).Methods("POST")
	trustAgentService.router.HandleFunc("/v2/binding-key-certificate", errorHandler(requiresPermission(getBindingKeyCertificate(), []string{getBindingKeyPerm}))).Methods("GET")
	trustAgentService.router.HandleFunc("/v2/tag", errorHandler(requiresPermission(setAssetTag(config, tpmFactory), []string{postDeployTagPerm}))).Methods("POST")
	trustAgentService.router.HandleFunc("/v2/host/application-measurement", errorHandler(requiresPermission(getApplicationMeasurement(), []string{postAppMeasurementPerm}))).Methods("POST")
	trustAgentService.router.HandleFunc("/v2/deploy/manifest", errorHandler(requiresPermission(deployManifest(), []string{postDeployManifestPerm}))).Methods("POST")

	return &trustAgentService, nil
}

func (service *TrustAgentService) Start() error {
	log.Trace("server:Start() Entering")
	defer log.Trace("server:Start() Leaving")

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
	httpLog := stdlog.New(logrus.StandardLogger().Writer(), "", 0)
	h := &http.Server{
		Addr:      fmt.Sprintf(":%d", service.port),
		Handler:   handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(os.Stderr, service.router)),
		ErrorLog:  httpLog,
		TLSConfig: tlsconfig,
	}

	// dispatch web server go routine
	go func() {
		if err := h.ListenAndServeTLS(constants.TLSCertFilePath, constants.TLSKeyFilePath); err != nil {
			secLog.Errorf("tasks/service:Start() %s", message.TLSConnectFailed)
			secLog.WithError(err).Fatalf("server:startServer() Failed to start HTTPS server: %s\n", err.Error())
			log.Tracef("%+v", err)
			stop <- syscall.SIGTERM
		}
	}()
	secLog.Info(message.ServiceStart)
	secLog.Infof("TrustAgent service is running: %d", service.port)

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		fmt.Printf("Failed to gracefully shutdown webserver: %v\n", err)
		log.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	secLog.Info(message.ServiceStop)
	return nil
}

// this requires lib/common to be sourced from
// replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v1.0/task/roles-and-permissions
// requiresPermission - ensures that correct permission is present in JWT
func requiresPermission(eh endpointHandler, permissionNames []string) endpointHandler {
	log.Trace("resource/service:requiresPermission() Entering")
	defer log.Trace("resource/service:requiresPermission() Leaving")
	return func(w http.ResponseWriter, r *http.Request) error {
		privileges, err := commContext.GetUserPermissions(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Could not get user roles from http context"))
			secLog.Errorf("resource/service:requiresPermission() %s Roles: %v | Context: %v", message.AuthenticationFailed, permissionNames, r.Context())
			return errors.Wrap(err, "resource/service:requiresPermission() Could not get user roles from http context")
		}
		reqPermissions := ct.PermissionInfo{Service: constants.AASServiceName, Rules: permissionNames}

		_, foundMatchingPermission := auth.ValidatePermissionAndGetRoleContext(privileges, reqPermissions,
			true)
		if !foundMatchingPermission {
			w.WriteHeader(http.StatusUnauthorized)
			secLog.Error(message.UnauthorizedAccess)
			secLog.Errorf("resource/service:requiresPermission() %s Insufficient privileges to access %s", message.UnauthorizedAccess, r.RequestURI)
			return &privilegeError{Message: "Insufficient privileges to access " + r.RequestURI, StatusCode: http.StatusUnauthorized}
		}
		secLog.Infof("resource/service:requiresPermission() %s - %s", message.AuthorizedAccess, r.RequestURI)
		return eh(w, r)
	}
}

// endpointHandler is the same as http.ResponseHandler, but returns an error that can be handled by a generic
// middleware handler
type endpointHandler func(w http.ResponseWriter, r *http.Request) error

func errorHandler(eh endpointHandler) http.HandlerFunc {
	log.Trace("resource/service:errorHandler() Entering")
	defer log.Trace("resource/service:errorHandler() Leaving")
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
