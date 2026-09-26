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

package mitmproxy

import "reflect"

// setBoolFieldIfPresent sets a bool field by name when the struct has one, and does
// nothing when it does not.
//
// The indirection exists so the test that uses it compiles against a tree where the
// field has not been added. Naming the field directly would turn "upstream behaves
// differently" into "upstream does not compile", and those are not the same finding:
// the second one passes as soon as a field exists, whether or not anything reads it.
func setBoolFieldIfPresent(target any, name string, value bool) {
	v := reflect.ValueOf(target).Elem().FieldByName(name)
	if v.IsValid() && v.Kind() == reflect.Bool && v.CanSet() {
		v.SetBool(value)
	}
}
