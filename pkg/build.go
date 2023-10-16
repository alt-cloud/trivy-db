package pkg

import (
	"github.com/alt-cloud/trivy-db/pkg/db"
	"github.com/alt-cloud/trivy-db/pkg/vulndb"
	"github.com/urfave/cli"
	"golang.org/x/xerrors"
)

func build(c *cli.Context) error {
	cacheDir := c.String("cache-dir")
	if err := db.Init(cacheDir); err != nil {
		return xerrors.Errorf("db initialize error: %w", err)
	}

	targets := c.StringSlice("only-update")
	updateInterval := c.Duration("update-interval")

	vdb := vulndb.New(cacheDir, updateInterval)
	if err := vdb.Build(targets); err != nil {
		return xerrors.Errorf("build error: %w", err)
	}

	return nil

}
