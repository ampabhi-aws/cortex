//go:build !integration
// +build !integration

package dbtest

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/logging"

	"github.com/cortexproject/cortex/pkg/configs/db"
	"github.com/cortexproject/cortex/pkg/util/flagext"
)

// Setup sets up stuff for testing, creating a new database
func Setup(t *testing.T) db.DB {
	require.NoError(t, logging.Setup("debug"))
	u, err := url.Parse("memory://")
	require.NoError(t, err)
	database, err := db.New(db.Config{
		URI: flagext.URLValue{URL: u},
	})
	require.NoError(t, err)
	return database
}

// Cleanup cleans up after a test
func Cleanup(t *testing.T, database db.DB) {
	require.NoError(t, database.Close())
}
