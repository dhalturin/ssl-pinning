/*
Copyright © 2025 Denis Khalturin
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
// prettier-ignore-end
package version

import (
	"runtime"
)

// gitCommit holds the git commit hash injected at build time via ldflags.
// Example: go build -ldflags "-X internal/version.gitCommit=abc123"
var (
	gitCommit = ""
	version   = ""
)

// BuildInfo contains version information about the application binary.
// Used for tracking deployments and debugging in production environments.
type BuildInfo struct {
	Version   string `json:"version,omitempty"`
	GitCommit string `json:"git_commit,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
}

// GetVersion returns the application version string.
// The version is typically injected at build time via ldflags.
func GetVersion() string {
	return version
}

// Get returns complete build information including version, git commit, and Go version.
// The git commit and version are injected at build time, while Go version is detected at runtime.
func Get() BuildInfo {
	return BuildInfo{GetVersion(), gitCommit, runtime.Version()}
}
