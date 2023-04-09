package vulnsrc

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alt"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/composer"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/glad"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/govulndb"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/mariner"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/node"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/photon"
	redhatoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/wolfi"
)

type VulnSrc interface {
	Name() types.SourceID
	Update(dir string) (err error)
}

var (
	// All holds all data sources
	All = []VulnSrc{
		// NVD
		//nvd.NewVulnSrc(),
		// OS packages
		alt.NewVulnSrc(),
		//alma.NewVulnSrc(),
		//alpine.NewVulnSrc(),
		//archlinux.NewVulnSrc(),
		//redhat.NewVulnSrc(),
		redhatoval.NewVulnSrc(),
		//debian.NewVulnSrc(),
		//ubuntu.NewVulnSrc(),
		//amazon.NewVulnSrc(),
		//oracleoval.NewVulnSrc(),
		//rocky.NewVulnSrc(),
		//susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
		//susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
		photon.NewVulnSrc(),
		mariner.NewVulnSrc(),
		wolfi.NewVulnSrc(),

		// Language-specific packages
		bundler.NewVulnSrc(),
		composer.NewVulnSrc(),
		node.NewVulnSrc(),
		ghsa.NewVulnSrc(),
		glad.NewVulnSrc(),
		govulndb.NewVulnSrc(),
		osv.NewVulnSrc(),
	}
)
