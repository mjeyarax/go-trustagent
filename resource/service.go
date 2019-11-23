/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/tpmprovider"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type TrustAgentService struct {
	port   int
	router *mux.Router
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
	trustAgentService.router.Use(newBasicAuth(config.TrustAgentService.Username, config.TrustAgentService.Password))
	trustAgentService.router.HandleFunc("/v2/aik", getAik).Methods("GET")
	trustAgentService.router.HandleFunc("/v2/host", getPlatformInfo).Methods("GET")
	trustAgentService.router.HandleFunc("/v2/tpm/quote", getTpmQuote(config, tpmFactory)).Methods("POST")
	trustAgentService.router.HandleFunc("/v2/binding-key-certificate", getBindingKeyCertificate).Methods("GET")
	trustAgentService.router.HandleFunc("/v2/tag", setAssetTag(config, tpmFactory)).Methods("POST")
	trustAgentService.router.HandleFunc("/v2/host/application-measurement", getApplicationMeasurement).Methods("POST")
	trustAgentService.router.HandleFunc("/v2/deploy/manifest", deployManifest).Methods("POST")

	return &trustAgentService, nil
}

func newBasicAuth(username string, password string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(httpWriter http.ResponseWriter, httpRequest *http.Request) {
			user, pass, ok := httpRequest.BasicAuth()

			if !ok {
				http.Error(httpWriter, "authorization failed", http.StatusUnauthorized)
				return
			}

			if user != username {
				http.Error(httpWriter, "authorization failed", http.StatusUnauthorized)
				return
			}

			if pass != password {
				http.Error(httpWriter, "authorization failed", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(httpWriter, httpRequest)
		})
	}
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

	// TODO dispatch Service status checker goroutine
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		log.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	return nil
}
