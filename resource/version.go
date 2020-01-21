/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"intel/isecl/go-trust-agent/util"
	"net/http"
)

// GetVersion handles GET /version
func getVersion(w http.ResponseWriter, r *http.Request) {
	log.Trace("resource/version:getVersion() Entering")
	defer log.Trace("resource/version:getVersion() Leaving")
	w.WriteHeader(http.StatusOK)
	log.Debugf("resource/version:getVersion() Trust Agent Version: %s CommitHash: %s", util.Version, util.GitHash)
	w.Write([]byte(fmt.Sprintf("%s-%s", util.Version, util.GitHash)))
}
