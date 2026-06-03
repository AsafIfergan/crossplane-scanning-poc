# Pin to a Crossplane v1 image — v2 dropped support for the traditional
# spec.resources[] Composition format that our fixtures use.
CROSSPLANE_IMAGE ?= xpkg.crossplane.io/crossplane/crossplane:v1.20.0
EXTENSIONS      := .crossplane/extensions.yaml

.PHONY: validate
validate:
	@command -v crossplane >/dev/null || { \
	  echo "crossplane CLI not found. Install with:"; \
	  echo "  curl -sL https://raw.githubusercontent.com/crossplane/crossplane/main/install.sh | sh"; \
	  echo "  mv crossplane /opt/homebrew/bin/   # or another dir on PATH"; \
	  exit 1; \
	}
	@FIXTURES=$$(find testdata -name '*.yaml' | tr '\n' ',' | sed 's/,$$//'); \
	  crossplane resource validate $(EXTENSIONS) "$$FIXTURES" \
	    --crossplane-image=$(CROSSPLANE_IMAGE) \
	    --skip-success-results
