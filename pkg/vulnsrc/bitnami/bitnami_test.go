package bitnami_test

import (
	"path/filepath"
	"testing"

	"github.com/alt-cloud/trivy-db/pkg/types"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/bitnami"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/bucket"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrctest"
)

var bucketName = bucket.Name(string(vulnerability.Bitnami), "Bitnami Vulnerability Database")

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						bucketName,
					},
					Value: types.DataSource{
						ID:   vulnerability.BitnamiVulndb,
						Name: "Bitnami Vulnerability Database",
						URL:  "https://github.com/bitnami/vulndb",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-11998",
						bucketName,
						"activemq",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"=5.15.12"},
						PatchedVersions:    []string{},
						VendorIDs:          []string{"BIT-2020-11998"},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-7059",
						bucketName,
						"php",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{
							">=7.2.0, <7.2.27",
							">=7.3.0, <7.3.14",
							">=7.4.0, <7.4.2",
						},
						PatchedVersions: []string{
							"7.2.27",
							"7.3.14",
							"7.4.2",
						},
						VendorIDs: []string{"BIT-2020-7059"},
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "JSON decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := bitnami.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
