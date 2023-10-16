package vulnsrc

import (
	"github.com/alt-cloud/trivy-db/pkg/types"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/alma"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/alpine"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/alt"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/amazon"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/bitnami"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/bundler"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/chainguard"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/composer"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/debian"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/glad"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/k8svulndb"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/mariner"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/node"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/nvd"
	oracleoval "github.com/alt-cloud/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/photon"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/redhat"
	redhatoval "github.com/alt-cloud/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/rocky"
	susecvrf "github.com/alt-cloud/trivy-db/pkg/vulnsrc/suse-cvrf"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/wolfi"
)

type VulnSrc interface {
	Name() types.SourceID
	Update(dir string) (err error)
}

var (
	// All holds all data sources
	All = []VulnSrc{
		// NVD
		nvd.NewVulnSrc(),
		// OS packages
		alt.NewVulnSrc(),
		alma.NewVulnSrc(),
		alpine.NewVulnSrc(),
		redhat.NewVulnSrc(),
		redhatoval.NewVulnSrc(),
		debian.NewVulnSrc(),
		ubuntu.NewVulnSrc(),
		amazon.NewVulnSrc(),
		oracleoval.NewVulnSrc(),
		rocky.NewVulnSrc(),
		susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
		susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
		photon.NewVulnSrc(),
		mariner.NewVulnSrc(),
		wolfi.NewVulnSrc(),
		chainguard.NewVulnSrc(),
		bitnami.NewVulnSrc(),

		k8svulndb.NewVulnSrc(),
		// Language-specific packages
		bundler.NewVulnSrc(),
		composer.NewVulnSrc(),
		node.NewVulnSrc(),
		ghsa.NewVulnSrc(),
		glad.NewVulnSrc(),
	}
)
