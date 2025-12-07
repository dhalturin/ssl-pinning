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
package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoot(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		wantStatus     int
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:       "GET request returns HTML page",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
			wantContains: []string{
				"<h1>Metrics</h1>",
				"<a href='/metrics'>Metrics</a>",
			},
			wantNotContain: []string{},
		},
		{
			name:       "POST request returns HTML page",
			method:     http.MethodPost,
			wantStatus: http.StatusOK,
			wantContains: []string{
				"<h1>Metrics</h1>",
				"<a href='/metrics'>Metrics</a>",
			},
			wantNotContain: []string{},
		},
		{
			name:         "HEAD request returns status OK",
			method:       http.MethodHead,
			wantStatus:   http.StatusOK,
			wantContains: []string{
				// HEAD requests should not return body content
			},
			wantNotContain: []string{},
		},
		{
			name:       "PUT request returns HTML page",
			method:     http.MethodPut,
			wantStatus: http.StatusOK,
			wantContains: []string{
				"<h1>Metrics</h1>",
				"<a href='/metrics'>Metrics</a>",
			},
			wantNotContain: []string{},
		},
		{
			name:       "response contains link to /metrics",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
			wantContains: []string{
				"/metrics",
				"href=",
			},
			wantNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a request
			req := httptest.NewRequest(tt.method, "/", nil)
			w := httptest.NewRecorder()

			// Call the handler
			Root(w, req)

			// Check status code
			if w.Code != tt.wantStatus {
				t.Errorf("Root() status = %v, want %v", w.Code, tt.wantStatus)
			}

			// Get response body
			body := w.Body.String()

			// Check that expected strings are present
			for _, want := range tt.wantContains {
				if !strings.Contains(body, want) {
					t.Errorf("Root() body does not contain %q, got: %v", want, body)
				}
			}

			// Check that unexpected strings are not present
			for _, notWant := range tt.wantNotContain {
				if strings.Contains(body, notWant) {
					t.Errorf("Root() body should not contain %q, got: %v", notWant, body)
				}
			}
		})
	}
}

func TestRoot_ContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	Root(w, req)

	// Check if Content-Type header is set (default text/plain or text/html)
	contentType := w.Header().Get("Content-Type")
	if contentType == "" {
		// Go's http.ResponseWriter sets Content-Type automatically based on content
		// If not explicitly set, it will be inferred from the body
		t.Log("Content-Type not explicitly set, will be inferred by http package")
	}
}

func TestRoot_MultipleRequests(t *testing.T) {
	// Test that multiple requests work correctly
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		Root(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Root() status = %v, want %v", i, w.Code, http.StatusOK)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Metrics") {
			t.Errorf("Request %d: Root() body does not contain 'Metrics'", i)
		}
	}
}

func TestRoot_ResponseBody(t *testing.T) {
	tests := []struct {
		name     string
		validate func(t *testing.T, body string)
	}{
		{
			name: "body is not empty",
			validate: func(t *testing.T, body string) {
				if body == "" {
					t.Error("Root() returned empty body")
				}
			},
		},
		{
			name: "body contains HTML tags",
			validate: func(t *testing.T, body string) {
				if !strings.Contains(body, "<") || !strings.Contains(body, ">") {
					t.Error("Root() body does not contain HTML tags")
				}
			},
		},
		{
			name: "body contains header tag",
			validate: func(t *testing.T, body string) {
				if !strings.Contains(body, "<h1>") || !strings.Contains(body, "</h1>") {
					t.Error("Root() body does not contain proper h1 tags")
				}
			},
		},
		{
			name: "body contains anchor tag with href",
			validate: func(t *testing.T, body string) {
				if !strings.Contains(body, "<a href=") {
					t.Error("Root() body does not contain anchor tag with href")
				}
			},
		},
		{
			name: "body ends with newline",
			validate: func(t *testing.T, body string) {
				if !strings.HasSuffix(body, "\n") {
					t.Error("Root() body does not end with newline")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			Root(w, req)

			tt.validate(t, w.Body.String())
		})
	}
}

func TestRoot_ConcurrentRequests(t *testing.T) {
	// Test concurrent access to Root handler
	const numRequests = 100
	done := make(chan bool, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()

			Root(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Root() status = %v, want %v", w.Code, http.StatusOK)
			}

			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}
}

func BenchmarkRoot(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		Root(w, req)
	}
}

func BenchmarkRoot_Parallel(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			Root(w, req)
		}
	})
}
