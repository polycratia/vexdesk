GO ?= go

.PHONY: build test fmt demo clean

build:
	$(GO) build -o vexdesk ./cmd/vexdesk

test:
	$(GO) vet ./...
	$(GO) test ./...

fmt:
	gofmt -w .

# The whole path over the fixtures: inventory, findings, document.
demo: build
	./vexdesk inventory testdata/sbom.cyclonedx.json
	@echo
	-./vexdesk match -sbom testdata/sbom.cyclonedx.json -advisories testdata/advisories
	@echo
	./vexdesk vex -sbom testdata/sbom.cyclonedx.json -advisories testdata/advisories \
		-decisions testdata/decisions.json -author "vexdesk demo"

clean:
	rm -f vexdesk
