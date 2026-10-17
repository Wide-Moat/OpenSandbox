// Copyright 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/log"
)

// resolveEgressToken returns the token the policy API will require, and whether it was
// derived (WM-27).
//
// With OPENSANDBOX_EGRESS_TOKEN_KEY unset this is upstream's behaviour byte for byte: the
// value of OPENSANDBOX_EGRESS_TOKEN as it is, empty meaning no authentication.
//
// With the key set and no explicit token, the token is
// hex(HMAC-SHA256(key, OPENSANDBOX_EGRESS_TOKEN_SUBJECT)) in lowercase: a pod template
// that is identical for every pod, a pool's, can then carry the key and the pod's own
// name, and whoever knows the key -- the server -- can compute each pod's token, while
// the token of one pod says nothing about another's. A key without a subject is refused:
// every pod would get the same token, or, worse, a caller would believe it was safe
// while the sidecar ran open. An explicit token wins over the key, with a warning.
func resolveEgressToken(getenv func(string) string) (token string, derived bool, err error) {
	token = getenv(constants.EnvEgressToken)
	key := getenv(constants.EnvEgressTokenKey)
	if key == "" {
		return token, false, nil
	}
	if strings.TrimSpace(token) != "" {
		log.Warnf("%s is set, so %s is ignored", constants.EnvEgressToken, constants.EnvEgressTokenKey)
		return token, false, nil
	}
	subject := getenv(constants.EnvEgressTokenSubject)
	if subject == "" {
		return "", false, fmt.Errorf("%s is set but %s is empty: refusing to run without a token",
			constants.EnvEgressTokenKey, constants.EnvEgressTokenSubject)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(subject))
	return hex.EncodeToString(mac.Sum(nil)), true, nil
}
