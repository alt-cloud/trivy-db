package alt

import (
	"encoding/json"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/alt-cloud/trivy-db/pkg/db"
	"github.com/alt-cloud/trivy-db/pkg/types"
	ustrings "github.com/alt-cloud/trivy-db/pkg/utils/strings"
	"github.com/alt-cloud/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	rootBucket = "alt"
	altDir     = "vuln-list-alt"
)

var (
	vendorCVEs []CveVendor
	source     = types.DataSource{
		ID:   vulnerability.ALT,
		Name: "alt",
		URL:  "https://rdb.altlinux.org",
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
	rootDir := filepath.Join(dir, altDir, "oval")
	branches, err := os.ReadDir(rootDir)
	if err != nil {
		return xerrors.Errorf("unable to list directory entries (%s): %w", rootDir, err)
	}

	advisories := map[bucket]AdvisorySpecial{}
	for _, branch := range branches {
		log.Printf("    Parsing %s", branch.Name())
		branchDir := filepath.Join(rootDir, branch.Name())
		products, err := os.ReadDir(branchDir)
		if err != nil {
			return xerrors.Errorf("unable to get a list of directory entries (%s): %w", branchDir, err)
		}

		for _, f := range products {
			definitions, err := parseOVAL(filepath.Join(branchDir, f.Name()))
			if err != nil {
				return xerrors.Errorf("failed to parse OVAL stream: %w", err)
			}

			advisories = vs.mergeAdvisories(advisories, definitions)

		}
	}
	if err = vs.putVendorCVEs(); err != nil {
		return xerrors.Errorf("put vendor cve error: %s", err)
	}
	if err = vs.save(advisories); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}

	return nil
}

func parseOVAL(dir string) (map[bucket]DefinitionSpecial, error) {
	tests, err := parseTests(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse tests: %w", err)
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
		if strings.Contains(advisory.ID, "unaffected") {
			continue
		}

		affectedPkgs := walkCriterion(advisory.Criteria, tests)
		for _, affectedPkg := range affectedPkgs {
			pkgName := affectedPkg.Name

			altID := vendorID(advisory.Metadata.References)

			var cveEntries []CveEntry
			vendorCve := vendorCVE(advisory.Metadata)
			cveEntries = append(cveEntries, vendorCve)

			vendorCVEs = append(vendorCVEs, CveVendor{CVE: vendorCve, Title: advisory.Metadata.Title,
				Description: advisory.Metadata.Description, References: toReferences(advisory.Metadata.References)})

			for _, bdu := range advisory.Metadata.Advisory.BDUs {
				bduEntry := CveEntry{
					ID:       bdu.CveID,
					Severity: severityFromImpact(bdu.Impact),
				}
				cveEntries = append(cveEntries, bduEntry)
				vendorCVEs = append(vendorCVEs, CveVendor{CVE: bduEntry, Title: "", Description: "", References: []string{bdu.Href}})
			}

			for _, cve := range advisory.Metadata.Advisory.Cves {
				cveEntries = append(cveEntries, CveEntry{
					ID:       cve.CveID,
					Severity: severityFromImpact(cve.Impact),
				})
			}

			if altID != "" {
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
			} else {
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
			arches = strings.Split(t.Arch, "|")
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

func (vs VulnSrc) mergeAdvisories(advisories map[bucket]AdvisorySpecial, defs map[bucket]DefinitionSpecial) map[bucket]AdvisorySpecial {
	for bkt, def := range defs {
		if old, ok := advisories[bkt]; ok {
			found := false
			for i := range old.Entries {
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

func (vs VulnSrc) save(advisories map[bucket]AdvisorySpecial) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, rootBucket, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}
		for bkt, advisory := range advisories {
			if err := vs.dbc.PutAdvisoryDetail(tx, bkt.vulnID, bkt.pkgName, []string{rootBucket}, advisory); err != nil {
				return xerrors.Errorf("failed to save ALT OVAL advisory: %w", err)
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

func vendorCVE(metadata Metadata) CveEntry {
	var id string
	for _, r := range metadata.References {
		if strings.Contains(r.RefID, "ALT") {
			id = r.RefID
		}
	}
	return CveEntry{ID: id, Severity: severityFromImpact(metadata.Advisory.Severity)}
}

func (vs VulnSrc) putVendorCVEs() error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range vendorCVEs {
			err := vs.putVendorVulnerabilityDetail(tx, cve)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}
func (vs VulnSrc) putVendorVulnerabilityDetail(tx *bolt.Tx, cve CveVendor) error {
	vuln := types.VulnerabilityDetail{
		CvssScore:    0,
		CvssVector:   "",
		CvssScoreV3:  0,
		CvssVectorV3: "",
		Severity:     cve.CVE.Severity,
		References:   cve.References,
		Title:        cve.Title,
		Description:  cve.Description,
	}
	if err := vs.dbc.PutVulnerabilityDetail(tx, cve.CVE.ID, vulnerability.ALT, vuln); err != nil {
		return xerrors.Errorf("failed to save ALT Vendor vulnerability: %w", err)
	}

	if err := vs.dbc.PutVulnerabilityID(tx, cve.CVE.ID); err != nil {
		return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
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

func toReferences(references []Reference) []string {
	var data []string
	for _, r := range references {
		data = append(data, r.RefURL)
	}
	return data
}
func cpeToList(cpes AffectedCpeList) []string {
	var list []string
	return append(list, cpes.Cpe...)
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
func vendorID(refs []Reference) string {
	for _, ref := range refs {
		switch ref.Source {
		case "ALTPU":
			return ref.RefID
		}
	}
	return ""
}
