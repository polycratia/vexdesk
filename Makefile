GO ?= go

.PHONY: build test fmt demo golden clean

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

# Re-record the documents in testdata/golden/ from the scanner fixtures. Run
# this when a change to the output is intended, and commit the result with it.
golden:
	$(GO) test ./cmd/vexdesk -run TestGoldenVEXDocuments -update

clean:
	rm -f vexdesk
