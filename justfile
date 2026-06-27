# gasypt-lite build recipes — run with `just` (https://github.com/casey/just)

default: build test

# build both binaries into build/
build:
    @mkdir -p build
    go build -o build/ ./cmd/cli
    go build -o build/ ./cmd/gasypt-gen

# run all tests
test:
    go test -count=1 ./...

# run tests with cross-compat (Windows only, needs Rust rasypt-lite)
test-cross:
    go test -count=1 -run TestCross -timeout 30s ./...

# run library-level benchmarks
bench:
    go test -bench=. -benchtime=1s -count=1 ./...

# lint
lint:
    go vet ./...

# remove build artifacts
clean:
    rm -rf build/
