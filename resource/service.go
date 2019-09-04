/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

import (
	"context"
	"errors"
	"net/http"
	"crypto/tls"
	"os"
	"time"
	"os/signal"
	"syscall"
	"fmt"

	log "github.com/sirupsen/logrus"
	stdlog "log"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type TrustAgentService struct {
	port			int
	router			*mux.Router
}

func CreateTrustAgentService (port int) (*TrustAgentService, error) {

	if(port == 0) {
		return nil, errors.New("Port cannot be zero")
	}

	trustAgentService := TrustAgentService {
		port : port,
	}

	// Register routes...
	trustAgentService.router = mux.NewRouter()
	sr := trustAgentService.router.PathPrefix("/v2").Subrouter()	
	func(setters ...func(*mux.Router)) {
		for _, s := range setters {
			s(sr)
		}
	} (SetAikRoutes, SetHostRoutes)
	
	return &trustAgentService, nil
}


func (service *TrustAgentService) Start() error {
	tlsconfig := &tls.Config {
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
	h := &http.Server {
		Addr:      fmt.Sprintf(":%d", service.port),
		Handler:   handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(os.Stderr, service.router)),
		ErrorLog:  httpLog,
		TLSConfig: tlsconfig,
	}

	// dispatch web server go routine
	go func() {
		// tlsCert := constants.TLSCertPath
		// tlsKey := constants.TLSKeyPath
		// if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
		// 	log.WithError(err).Info("Failed to start HTTPS server")
		// 	stop <- syscall.SIGTERM
		// }

		// KWT:  TLS setup
		if err := h.ListenAndServe(); err != nil {
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