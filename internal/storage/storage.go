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
package storage

import (
	"context"
	"fmt"

	"ssl-pinning/internal/storage/filesystem"
	"ssl-pinning/internal/storage/memory"
	"ssl-pinning/internal/storage/postgres"
	"ssl-pinning/internal/storage/redis"
	"ssl-pinning/internal/storage/types"
)

// New creates and initializes a storage backend based on the specified storage type.
// Supported storage types:
//   - StorageFS: file system-based storage
//   - StorageMemory: in-memory storage (ephemeral)
//   - StorageRedis: Redis-based storage
//   - StoragePostgres: PostgreSQL database storage
//
// Configuration is applied via functional options (app ID, DSN, dump directory, etc.).
// Returns an error if the storage type is invalid or initialization fails.
func New(ctx context.Context, storage types.StorageType, opts ...types.Option) (types.Storage, error) {
	switch storage {
	case types.StorageFS:
		return filesystem.New(ctx, opts...)

	case types.StorageMemory:
		return memory.New(ctx, opts...)

	case types.StorageRedis:
		return redis.New(ctx, opts...)

	case types.StoragePostgres:
		return postgres.New(ctx, opts...)

	default:
		return nil, fmt.Errorf("invalid storage type: %s", storage)
	}
}
