// Trust Agent
//
// The Trust Agent acts as a primary interface between the Host, TPM and the Host Verification Service.
// It maintains the ownership of the server’s Trusted Platform Module and allows the secure attestation quotes
// to be sent to the Host Verification Service.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 2.2
//  Host: trustagent.server.com:1443
//  BasePath: /v2
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token>**
//
// swagger:meta
package docs

import "intel/isecl/go-trust-agent/v3/util"

// VersionResponseInfo response payload
// swagger:response VersionResponseInfo
type VersionResponseInfo struct {
	// in:body
	Body util.VersionInfo
}

// swagger:operation GET /version Version getVersion
// ---
// description: Retrieves the version of trust agent.
//
// produces:
// - application/json
// responses:
//   "200":
//     description: Successfully retrieved the version of trust agent.
//     schema:
//       "$ref": "#/definitions/VersionInfo"
//
// x-sample-call-endpoint: https://trustagent.server.com:1443/version
// x-sample-call-output: |
//    {
//        "major": 1,
//        "minor": 0,
//        "patch": 0,
//        "commit": "34d89de",
//        "built": "2020-04-18T14:52:14Z",
//        "version_string": "Trust Agent v2.2.0-34d89de\nBuilt 2020-05-04T14:52:14Z\n"
//    }
// ---
