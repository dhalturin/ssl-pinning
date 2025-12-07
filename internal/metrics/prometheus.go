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
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ExpireItem is a composite key for certificate expiration metrics.
// It combines the certificate hash key and fully qualified domain name (FQDN)
// to uniquely identify a certificate expiration metric in Prometheus.
type ExpireItem struct {
	Key  string
	FQDN string
}

// Collector is a Prometheus collector that tracks SSL pinning metrics.
// It maintains counters for validation errors per file and certificate expiration times per domain.
// Implements prometheus.Collector interface for custom metrics collection.
type Collector struct {
	errors  sync.Map
	expires sync.Map
}

// NewCollector creates and registers a new Collector instance with Prometheus.
// The collector tracks SSL pinning errors and certificate expiration times.
// Panics if registration with Prometheus fails.
func NewCollector() *Collector {
	c := new(Collector)
	// c.errors = sync.Map{}
	// c.expires = sync.Map{}
	prometheus.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector interface.
// Returns an empty description as metrics are dynamically generated during collection.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector interface.
// Gathers and sends all SSL pinning metrics to Prometheus:
// - ssl_pinning_errors: number of validation errors per file (gauge, cleared after collection)
// - ssl_pinning_expire: certificate expiration time in seconds per key/FQDN (gauge)
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.errors.Range(func(k, v any) bool {
		file := k.(string)
		val := v.(float64)

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"ssl_pinning_errors",
				"Number of pinning validation errors per file",
				[]string{"file"},
				nil,
			),
			prometheus.GaugeValue,
			val,
			file,
		)

		c.ClearError(file)
		return true
	})

	c.expires.Range(func(k, v any) bool {
		item := k.(ExpireItem)
		expire := v.(float64)

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"ssl_pinning_expire",
				"Certificate expiration timestamp or seconds until expiry",
				[]string{"key", "fqdn"},
				nil,
			),
			prometheus.GaugeValue,
			expire,
			item.Key,
			item.FQDN,
		)
		return true
	})
}

// IncError increments the error counter for a specific file.
// Used to track failed SSL certificate validation attempts.
func (c *Collector) IncError(file string) {
	val, _ := c.errors.LoadOrStore(file, 0.0)
	c.errors.Store(file, val.(float64)+1)
}

// ClearError resets the error counter for a specific file to zero.
// Automatically called after metrics collection to prevent error accumulation.
func (c *Collector) ClearError(file string) {
	c.errors.Store(file, 0.0)
}

// SetExpire updates the certificate expiration metric for a specific key and FQDN.
// The expire value represents seconds until certificate expiration.
func (c *Collector) SetExpire(key, fqdn string, expire float64) {
	c.expires.Store(ExpireItem{Key: key, FQDN: fqdn}, expire)
}

// ClearExpire removes the certificate expiration metric for a specific key and FQDN.
// Used when a certificate or domain is removed from monitoring.
func (c *Collector) ClearExpire(key, fqdn string) {
	c.expires.Delete(ExpireItem{Key: key, FQDN: fqdn})
}
