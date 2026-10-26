module github.com/oskoi/monotone-go

go 1.23.0

require (
	github.com/ebitengine/purego v0.9.1
	golang.org/x/sys v0.33.0
)

retract [v0.0.0, v0.11.2] // use the default branch.
