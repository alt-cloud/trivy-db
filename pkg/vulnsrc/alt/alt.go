package alt

import (
	"encoding/json"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	rootBucket = "ALT"
)

var (
	altDir = filepath.Join("oval", "alt")

	moduleRegexp = regexp.MustCompile(`Module\s+(.*)\s+is enabled`)

	source = types.DataSource{
		ID:   vulnerability.ALT,
		Name: "ALT",
		URL:  "",
	}
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return vulnerability.ALT
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", altDir)
	branches, err := os.ReadDir(rootDir)
	if err != nil {
		return xerrors.Errorf("unable to list directory entries (%s): %w", rootDir, err)
	}

	advisories := map[bucket]AdvisorySpecial{}
	for _, branch := range branches {
		branchDir := filepath.Join(rootDir, branch.Name())
		products, err := os.ReadDir(branchDir)
		if err != nil {
			return xerrors.Errorf("unable to get a list of directory entries (%s): %w", branchDir, err)
		}

		for _, f := range products {
			//if !f.IsDir() {
			//	continue
			//}

			definitions, err := parseOVALStream(filepath.Join(branchDir, f.Name()))
			if err != nil {
				return xerrors.Errorf("failed to parse OVAL stream: %w", err)
			}

			advisories = vs.mergeAdvisories(advisories, definitions)

		}
	}
	if err = vs.save(advisories); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}

	return nil
}

func parseOVALStream(dir string) (map[bucket]DefinitionSpecial, error) {
	log.Printf("    Parsing %s", dir)

	// Parse tests
	tests, err := parseTests(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse ovalTests: %w", err)
	}

	var definitions Definitions

	err = unmarshalJSONFile(&definitions, path.Join(dir, "definitions.json"))
	if err != nil {
		return nil, xerrors.Errorf("ALT OVAL parse error: %w", err)
	}

	return parseDefinitions(definitions, tests), nil
}

func parseDefinitions(definitions Definitions, tests map[string]RpmInfoTestSpecial) map[bucket]DefinitionSpecial {
	defs := map[bucket]DefinitionSpecial{}

	for _, advisory := range definitions.Definition {
		// Skip unaffected vulnerabilities
		if strings.Contains(advisory.ID, "unaffected") {
			continue
		}

		// Parse criteria
		affectedPkgs := walkCriterion(advisory.Criteria, tests)
		for _, affectedPkg := range affectedPkgs {
			pkgName := affectedPkg.Name

			altID := vendorID(advisory.Metadata.References)

			var cveEntries []CveEntry
			for _, cve := range advisory.Metadata.Advisory.Cves {
				cveEntries = append(cveEntries, CveEntry{
					ID:       cve.CveID,
					Severity: severityFromImpact(cve.Impact),
				})
			}

			if altID != "" { // For patched vulnerabilities
				bkt := bucket{
					pkgName: pkgName,
					vulnID:  altID,
				}
				defs[bkt] = DefinitionSpecial{
					Entry: Entry{
						Cves:            cveEntries,
						FixedVersion:    affectedPkg.FixedVersion,
						AffectedCPEList: cpeToList(advisory.Metadata.Advisory.AffectedCpeList),
						Arches:          affectedPkg.Arches,
					},
				}
			} else { // For unpatched vulnerabilities
				for _, cve := range cveEntries {
					bkt := bucket{
						pkgName: pkgName,
						vulnID:  cve.ID,
					}
					defs[bkt] = DefinitionSpecial{
						Entry: Entry{
							Cves: []CveEntry{
								{
									Severity: cve.Severity,
								},
							},
							FixedVersion:    affectedPkg.FixedVersion,
							AffectedCPEList: cpeToList(advisory.Metadata.Advisory.AffectedCpeList),
							Arches:          affectedPkg.Arches,
						},
					}
				}
			}
		}
	}

	return defs
}

func walkCriterion(cri Criteria, tests map[string]RpmInfoTestSpecial) []pkg {
	var packages []pkg

	for _, c := range cri.Criterions {
		t, ok := tests[c.TestRef]
		if !ok {
			continue
		}

		var arches []string
		if t.Arch != "" {
			arches = strings.Split(t.Arch, "|") // affected arches are merged with '|'(e.g. 'aarch64|ppc64le|x86_64')
		}

		packages = append(packages, pkg{
			Name:         t.Name,
			FixedVersion: t.FixedVersion,
			Arches:       arches,
		})
	}

	if len(cri.Criterias) == 0 {
		return packages
	}

	for _, c := range cri.Criterias {
		pkgs := walkCriterion(c, tests)
		if len(pkgs) != 0 {
			packages = append(packages, pkgs...)
		}
	}
	return packages
}

func vendorID(refs []Reference) string {
	for _, ref := range refs {
		switch ref.Source {
		case "ALTPU":
			return ref.RefID
		}
	}
	return ""
}

func severityFromImpact(sev string) types.Severity {
	switch strings.ToLower(sev) {
	case "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}

func (vs VulnSrc) mergeAdvisories(advisories map[bucket]AdvisorySpecial, defs map[bucket]DefinitionSpecial) map[bucket]AdvisorySpecial {
	for bkt, def := range defs {
		if old, ok := advisories[bkt]; ok {
			found := false
			for i := range old.Entries {
				// New advisory should contain a single fixed version and list of arches.
				if old.Entries[i].FixedVersion == def.Entry.FixedVersion && archesEqual(old.Entries[i].Arches, def.Entry.Arches) {
					found = true
					old.Entries[i].AffectedCPEList = ustrings.Merge(old.Entries[i].AffectedCPEList, def.Entry.AffectedCPEList)
				}
			}
			if !found {
				old.Entries = append(old.Entries, def.Entry)
			}
			advisories[bkt] = old
		} else {
			advisories[bkt] = AdvisorySpecial{
				Entries: []Entry{def.Entry},
			}
		}
	}

	return advisories
}

func archesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (vs VulnSrc) save(advisories map[bucket]AdvisorySpecial) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, rootBucket, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}
		for bkt, advisory := range advisories {
			if err := vs.dbc.PutAdvisoryDetail(tx, bkt.vulnID, bkt.pkgName, []string{rootBucket}, advisory); err != nil {
				return xerrors.Errorf("failed to save Red Hat OVAL advisory: %w", err)
			}

			if err := vs.dbc.PutVulnerabilityID(tx, bkt.vulnID); err != nil {
				return xerrors.Errorf("failed to put severity: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("batch update error: %w", err)
	}
	return nil
}

func (vs VulnSrc) Get(pkgName, cpe string) ([]types.Advisory, error) {
	rawAdvisories, err := vs.dbc.ForEachAdvisory([]string{rootBucket}, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("unable to iterate advisories: %w", err)
	}

	var advisories []types.Advisory
	for vulnID, v := range rawAdvisories {
		if len(v.Content) == 0 {
			continue
		}

		var adv AdvisorySpecial
		if err = json.Unmarshal(v.Content, &adv); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
		}

		for _, entry := range adv.Entries {
			if !contains(entry.AffectedCPEList, cpe) {
				continue
			}

			for _, cve := range entry.Cves {
				advisory := types.Advisory{
					Severity:     cve.Severity,
					FixedVersion: entry.FixedVersion,
					Arches:       entry.Arches,
				}

				if strings.HasPrefix(vulnID, "CVE-") {
					advisory.VulnerabilityID = vulnID
				} else {
					advisory.VulnerabilityID = cve.ID
					advisory.VendorIDs = []string{vulnID}
				}

				advisories = append(advisories, advisory)
			}
		}
	}

	return advisories, nil
}

func contains(lst []string, val string) bool {
	for _, e := range lst {
		if e == val {
			return true
		}
	}
	return false
}

func cpeToList(cpes []CPE) []string {
	var list []string
	for _, cpe := range cpes {
		list = append(list, cpe.Cpe)
	}
	return list
}
