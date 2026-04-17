# Crossplane IaC Scanning POC

Proof of concept for scanning Crossplane manifests for cloud misconfigurations, following the same patterns as Terraform/Pulumi IaC scanning.

**Jira:** [WZ-34489](https://wiz-io.atlassian.net/browse/WZ-34489)

## Architecture

```
Crossplane YAML files (.yaml/.yml)
        ↓
┌─────────────────────────────────────────┐
│  Detection (CrossPlaneRegex)            │
│  Matches *.crossplane.io + *.upbound.io │
└────────────┬────────────────────────────┘
             ↓
┌─────────────────────────────────────────┐
│  Parser                                 │
│  - Split multi-document YAML (---)      │
│  - Group by Kind + metadata.name        │
│  - Extract Composition nested resources │
└────────────┬────────────────────────────┘
             ↓
         Restructured Document:
         {
           "resource": {
             "VPC":    { "my-vpc": { ... } },
             "Subnet": { "subnet-a": { ... } }
           }
         }
             ↓
┌─────────────────────────────────────────┐
│  Rego Policy Evaluation                 │
│  document.resource.RDSInstance[name]    │
│  (same pattern as Terraform)            │
└─────────────────────────────────────────┘
```

### Key Design Decisions

1. **Terraform-like document structure** — Resources keyed by `Kind` + `metadata.name` so Rego policies use `document.resource.<Kind>[name]` (cheap hash lookup, no `input.document[_]` scans)
2. **Upbound support** — Regex detects both `*.crossplane.io` and `*.upbound.io` (modern industry standard)
3. **Composition extraction** — Resources nested under `spec.resources[].base` are flattened into the same resource map
4. **Cross-resource correlation via Rego library** — `crossplaneLib.associatedByRef()` checks `*Ref` fields (same approach as Pulumi's `depends()`)
5. **Pipeline-mode compositions skipped** — Modern compositions using `mode: Pipeline` + function refs have no inline resources to extract

## Running Tests

```bash
go test -v ./parser/
```

### What the tests cover

| Test | What it validates |
|------|-------------------|
| `TestIsCrossplaneFile` | Regex detection: crossplane.io, upbound.io, rejects K8s/KNative |
| `TestParseStandaloneResources` | Multi-doc YAML → grouped by Kind+name (VPC, 2 Subnets, 2 SecurityGroups) |
| `TestParseComposition` | Composition nested resources extracted to flat map |
| `TestParseUpbound` | Upbound provider apiVersions parsed identically |
| `TestParseMixed` | Standalone + Composition in same file both land in resource map |
| `TestRegoPolicy_RDSNotEncrypted` | End-to-end: YAML → parse → Rego → detects unencrypted RDS |
| `TestRegoPolicy_RDSNotEncrypted_Composition` | Same policy detects unencrypted RDS inside a Composition |
| `TestRegoPolicy_SecurityGroupOpenIngress` | Detects 0.0.0.0/0 ingress rule |
| `TestRegoPolicy_SubnetVPCRef` | Cross-resource correlation: subnets reference existing VPC (no finding) |
| `TestRegoPolicy_MixedStandaloneAndComposition` | Only flags the unencrypted composed resource, not the encrypted standalone |

## File Structure

```
├── parser/
│   ├── parser.go           # Crossplane YAML parser + document restructuring
│   └── parser_test.go      # Tests: parsing + Rego evaluation
├── rego/
│   ├── crossplane.rego     # Shared library (getResourceName, associatedByRef, etc.)
│   ├── rds_not_encrypted.rego
│   ├── security_group_open_ingress.rego
│   └── subnet_without_vpc_ref.rego
└── testdata/
    ├── standalone/         # Real-world standalone managed resources
    ├── composition/        # Traditional Composition with nested resources
    ├── upbound/            # Upbound provider format
    └── mixed/              # Standalone + Composition in one file
```

## Integration into wiz monorepo

To integrate this into the main IaC scanning pipeline (`iacscanlib`):

1. **Pipeline wiring** — Register `CrossplanePipeline` using `BuildGenericIACPipeline` (same as Pulumi/Ansible). Already prototyped in branch `asafi/WZ-34489-crossplane_scanning` ([PR #127363](https://github.com/wiz-sec/wiz/pull/127363)).

2. **Custom enrichment step** — Replace standard `NewMetadataEnrichmentPipeline` with `NewCrossplaneMetadataEnrichmentPipeline` that restructures docs before creating `FileMetadata`.

3. **Type mappings** — Add `CROSSPLANE` to: GQL enum, proto `IacOpaMatcherType`, proto `ResourceSubType`, proto `IACPlatform`, all converter BiMaps, PreviewHub feature flag. (All done in the PR, needs `wze task gen-proto` + `gen-gql`.)

4. **Regex update** — `CrossPlaneRegex` needs exporting from `analyzer.go` and updated to include `upbound.io`.

5. **Policies** — Rego policies follow standard query structure (`query.rego` + `metadata.json` + `test/` fixtures).
