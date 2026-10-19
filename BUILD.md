# Building the binary yourself

Release binaries exist for Linux amd64, Linux arm64 and Windows amd64. For any other CPU, or if you want to build what you run, build it from source.

## Requirements

- The Go version named in `go.mod`, or newer (`go version`).
- Network access to download the Go modules the first time (see `DEPENDENCIES`).

## Build

```sh
git clone https://github.com/danang-id/server-hardening.git
cd server-hardening
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o hardening ./cmd/hardening
```

To build for another system, set `GOOS` and `GOARCH`. For example, a 32-bit ARM Linux server:

```sh
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o hardening ./cmd/hardening
```

`go tool dist list` shows every combination. The tool only does something useful on a system that has controls (see the table in `README.md`). On any other system it stops at the start and says why.

## Run

The binary is interactive and must run as root (`--dry-run` does not need it):

```sh
sudo ./hardening --dry-run   # show what would run, in order, and change nothing
sudo ./hardening             # choose controls and apply them
sudo ./hardening --revert    # choose controls to undo
sudo ./hardening --plain     # simple prompts instead of the full-screen interface
```

To see the interface without a server, on any computer with Go:

```sh
go run ./cmd/hardening --demo            # apply, on a pretend server
go run ./cmd/hardening --demo --revert   # revert
```

The demo uses the real screens and the real control list with their descriptions. Applying only waits and writes log lines, so nothing on your computer changes.

## Check before you trust it

```sh
gofmt -l .        # prints nothing
go vet ./...
go test ./...
```

The tests run without root and change nothing on your machine: controls work on a temporary directory and a fake command runner. They do not replace a run on a test server. Take a snapshot of a virtual machine, run the tool there first, and read the log.

## Release binaries

A tag such as `v0.1.0` starts `.github/workflows/release.yml`. It runs the tests, builds the three binaries, writes `SUPPORTED` (the output of `hardening --print-support`, which `hardening.sh` reads to decide whether the machine is supported before it downloads anything), copies `LICENSE`, builds `THIRD_PARTY_LICENSES` with `scripts/third-party-licenses.sh`, writes a `SHA256SUMS` file that covers all of them, and publishes everything on the release. The entry scripts download from the latest release and check what they download against that file. Publish the script and the release together: `hardening.sh` passes `--skip-welcome` to the binary, so the release must come from a version that has that flag.
