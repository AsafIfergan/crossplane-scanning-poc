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
│  Parser (dumb YAML→JSON)                │
│  - Split multi-document YAML (---)      │
│  - Preserve each document as written    │
│    (Composition stays intact; nothing   │
│     is renamed, flattened, or dropped)  │
└────────────┬────────────────────────────┘
             ↓
         Raw docs list (input.document[]):
         [
           { kind: "VPC",         metadata: {name: "my-vpc"},   spec: {...} },
           { kind: "Subnet",      metadata: {name: "subnet-a"}, spec: {...} },
           { kind: "Composition", spec: { resources: [
               { name: "rds", base: { kind: "RDSInstance", ... }, patches: [...] }
           ]}}
         ]
             ↓
┌─────────────────────────────────────────┐
│  Rego Policy Evaluation                 │
│  cp_lib.managedResourcesOf("RDSInstance")[_]
│  (yields standalone + composed alike)   │
└─────────────────────────────────────────┘
```

### Key Design Decisions

1. **Parser is dumb** — Each YAML document is preserved exactly as written. Multi-doc files are split into `input.document[]`, but no fields are dropped, renamed, or restructured. `Composition.spec.resources[]` (including `patches`) stays intact.
2. **Upbound support** — Regex detects both `*.crossplane.io` and `*.upbound.io` (modern industry standard).
3. **Composition handling lives in Rego** — `cp_lib.managedResourcesOf(kind)` yields a uniform result for both standalone managed resources and resources nested under `Composition.spec.resources[].base`. Policies stay agnostic of where a resource was declared.
4. **Cross-resource correlation via Rego library** — `cp_lib.resourceExists(kind, name)` and `cp_lib.associatedByRef()` cover existence checks and `*Ref` field lookups (same approach as Pulumi's `depends()`).
5. **Pipeline-mode compositions** — Modern compositions using `mode: Pipeline` + function refs have no inline resources for `managedResourcesOf` to find; only the Composition wrapper itself appears in the input.

### Provider families

Crossplane's AWS coverage is split across two provider families with different CRD shapes:

- **Legacy** — `crossplane-contrib/provider-aws`. apiVersion `<service>.aws.crossplane.io/v1beta1`. Hand-authored CRDs, maintenance-mode only.
- **Upbound** — `upbound/provider-family-aws`. apiVersion `<service>.aws.upbound.io/v1beta1` (or later). Auto-generated from Terraform's AWS provider schemas. Standard for new Crossplane installs.

The shapes diverge in three ways the policies must handle:

| Concern | Legacy | Upbound |
|---|---|---|
| RDS kind | `RDSInstance` | `Instance` (collides with EC2's `Instance` — disambiguate via apiVersion) |
| SG ingress | inline `spec.forProvider.ingress[].ipRanges[].cidrIp` | separate top-level `SecurityGroupIngressRule` with `spec.forProvider.cidrIpv4` |
| Spec sections | `spec.forProvider` only | `spec.forProvider` **and** `spec.initProvider` (late-bound) |

Each Rego rule carries one WizPolicy block per family. The shared library exposes `isAWSLegacy`, `isAWSUpbound`, `isAWSUpboundRDS`, `isAWSUpboundEC2`, `isAWS`, and `mergedSpec` (merges `forProvider` + `initProvider`) so rules don't have to repeat the family-detection or spec-flattening logic.

## Running Tests

```bash
go test -v ./parser/
```

## Validating fixtures against real provider CRDs

`make validate` runs `crossplane resource validate` over every YAML file in `testdata/`, checking each manifest against the real provider CRDs downloaded from `xpkg.upbound.io`. Catches typo'd field names, missing required fields, wrong apiVersion strings, type mismatches.

```bash
make validate
```

One-time setup — install the Crossplane CLI:

```bash
curl -sL https://raw.githubusercontent.com/crossplane/crossplane/main/install.sh | sh
mv crossplane /opt/homebrew/bin/   # or another dir on PATH
```

Provider packages used are listed in `.crossplane/extensions.yaml` (legacy `crossplane-contrib/provider-aws` + Upbound `provider-aws-rds`/`provider-aws-ec2`). They're downloaded once to `~/.crossplane/cache/` on first run.

The Makefile pins the Crossplane image to `v1.20.0` for validation because Crossplane v2 dropped support for the traditional `spec.resources[]` Composition format that our fixtures (and many real-world Crossplane installs) still use.

### What the tests cover

| Test | What it validates |
|------|-------------------|
| `TestIsCrossplaneFile` | Regex detection: crossplane.io, upbound.io, rejects K8s/KNative |
| `TestParseStandaloneResources` | Multi-doc YAML → list of 5 docs, each preserved as written |
| `TestParseComposition` | Composition stays as a single doc; nested `spec.resources[].base` + `patches` preserved |
| `TestParseUpbound` | Upbound provider apiVersions parsed identically |
| `TestParseMixed` | Standalone + Composition in same file both appear in the docs list |
| `TestRegoPolicy_RDSNotEncrypted` | Table-driven: 8 cases — pass/fail × {legacy,upbound}-{standalone,composition} |
| `TestRegoPolicy_SecurityGroupOpenIngress` | Table-driven: 8 cases — legacy uses inline `SecurityGroup.ingress`, Upbound uses separate `SecurityGroupIngressRule` |
| `TestRegoPolicy_SubnetWithoutVPCRef` | Table-driven: 8 cases — cross-resource correlation via `resourceExists("VPC", name)`; legacy and Upbound share the same shape |

## File Structure

```
├── parser/
│   ├── parser.go           # Multi-doc YAML → list of JSON-compatible maps
│   └── parser_test.go      # Tests: parsing + Rego evaluation
├── rego/
│   ├── crossplane.rego     # Shared library (managedResourcesOf, resourceExists, associatedByRef, ...)
│   ├── rds_not_encrypted.rego
│   ├── security_group_open_ingress.rego
│   └── subnet_without_vpc_ref.rego
└── testdata/
    ├── rds_not_encrypted/             # Fixtures for the unencrypted-RDS rule
    │   ├── pass/{legacy,upbound}-{standalone,composition}.yaml
    │   └── fail/{legacy,upbound}-{standalone,composition}.yaml
    ├── security_group_open_ingress/   # Fixtures for the 0.0.0.0/0 ingress rule
    │   ├── pass/{legacy,upbound}-{standalone,composition}.yaml
    │   └── fail/{legacy,upbound}-{standalone,composition}.yaml
    ├── subnet_without_vpc_ref/        # Fixtures for the missing-VPC-ref rule
    │   ├── pass/{legacy,upbound}-{standalone,composition}.yaml
    │   └── fail/{legacy,upbound}-{standalone,composition}.yaml
    └── parser/                        # Fixtures used only by parser-shape tests
        ├── multi-doc-standalone.yaml  # 5-doc file: VPC + 2 Subnets + 2 SecurityGroups
        ├── composition.yaml           # Single Composition with patches
        ├── upbound.yaml               # Upbound provider apiVersion
        └── mixed.yaml                 # Standalone + Composition in one file
```

Each per-rule folder has 8 fixtures: `{pass,fail}/{legacy,upbound}-{standalone,composition}.yaml`. Pass fixtures must produce no findings for that rule; fail fixtures must produce at least one.

## Integration into wiz monorepo

To integrate this into the main IaC scanning pipeline (`iacscanlib`):

1. **Pipeline wiring** — Register `CrossplanePipeline` using `BuildGenericIACPipeline` (same as Pulumi/Ansible). Already prototyped in branch `asafi/WZ-34489-crossplane_scanning` ([PR #127363](https://github.com/wiz-sec/wiz/pull/127363)).

2. **Custom enrichment step** — Replace standard `NewMetadataEnrichmentPipeline` with `NewCrossplaneMetadataEnrichmentPipeline` that restructures docs before creating `FileMetadata`.

3. **Type mappings** — Add `CROSSPLANE` to: GQL enum, proto `IacOpaMatcherType`, proto `ResourceSubType`, proto `IACPlatform`, all converter BiMaps, PreviewHub feature flag. (All done in the PR, needs `wze task gen-proto` + `gen-gql`.)

4. **Regex update** — `CrossPlaneRegex` needs exporting from `analyzer.go` and updated to include `upbound.io`.

5. **Policies** — Rego policies follow standard query structure (`query.rego` + `metadata.json` + `test/` fixtures).
