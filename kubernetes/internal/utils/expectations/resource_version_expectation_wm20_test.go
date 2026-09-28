// Copyright 2025 The OpenSandbox Authors
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

package expectations

import (
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The duration IsSatisfied reports is how long the CURRENT expectation has gone
// unmet. BatchSandbox status writes use it as a 10s safety valve: past it they write
// even though the cache has not caught up. When a newer write replaced the expectation,
// the clock kept the timestamp of the older one, so a write made a moment ago read as
// long overdue -- "unsatisfiedDuration 1m13s" in the PauseResume e2e controller log,
// in the same second as the pause handler's own status write, and the valve fired on a
// cache that was one update behind.
func TestWM20ExpectRestartsTheStalenessClock(t *testing.T) {
	uid := metav1.ObjectMeta{UID: "wm20"}
	at := func(rv string) *v1.Pod {
		meta := uid
		meta.ResourceVersion = rv
		return &v1.Pod{ObjectMeta: meta}
	}
	const idle = 300 * time.Millisecond

	e := NewResourceVersionExpectation()
	e.Expect(at("10"))
	if ok, _ := e.IsSatisfied(at("9")); ok {
		t.Fatal("fixture: a cache at 9 must not satisfy an expectation of 10")
	}

	// The object then sits where nothing asks (a sandbox in Pausing), and the next
	// write records a newer expectation.
	time.Sleep(idle)
	e.Expect(at("12"))

	ok, dur := e.IsSatisfied(at("11"))
	if ok {
		t.Fatal("a cache at 11 must not satisfy an expectation of 12")
	}
	if dur >= idle {
		t.Fatalf("an expectation recorded just now reports it has been unmet for %s: "+
			"the clock of the expectation it replaced was kept", dur)
	}
}
