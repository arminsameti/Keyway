VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin/xray-friendly
# Separate path: go build refuses to overwrite a lipo'd fat binary.
UNIBIN  := bin/xray-friendly-universal

.PHONY: build test test-engines test-native vet lint smoke run app universal snapshots clean
build:
	@mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/xray-friendly

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

smoke: build
	./scripts/smoke.sh $(BIN)

run: build
	$(BIN)

universal:
	@mkdir -p bin
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/xf-arm64 ./cmd/xray-friendly
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/xf-amd64 ./cmd/xray-friendly
	lipo -create -output $(UNIBIN) bin/xf-arm64 bin/xf-amd64
	rm -f bin/xf-arm64 bin/xf-amd64

# macOS app bundle: the SwiftUI app (universal) plus the universal Go backend.
APP         := dist/XrayFriendly.app
SWIFT_BUILD := swift build -c release --package-path native --arch arm64 --arch x86_64
app: universal
	$(SWIFT_BUILD)
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp "$$($(SWIFT_BUILD) --show-bin-path)/XrayFriendly" $(APP)/Contents/MacOS/XrayFriendly
	cp $(UNIBIN) $(APP)/Contents/MacOS/xray-friendly
	cp native/Info.plist $(APP)/Contents/Info.plist
	cp assets/icon.icns $(APP)/Contents/Resources/AppIcon.icns
	codesign --force --sign - $(APP)/Contents/MacOS/xray-friendly
	codesign --force --sign - $(APP)/Contents/MacOS/XrayFriendly
	codesign --force --sign - $(APP)
	codesign --verify --strict $(APP)

# Feed every generated config (all protocols, chains, bridge segments) to the
# installed real engines: sing-box check and xray -test. Needs both engines
# downloaded once (Settings > Engines).
test-engines:
	SINGBOX_BIN="$$(ls -d $$HOME/.xray-friendly/engines/sing-box/v*/sing-box | tail -1)" \
	XRAY_BIN="$$(ls -d $$HOME/.xray-friendly/engines/xray/v*/xray | tail -1)" \
	go test -count=1 -run RealEngine -v ./internal/singbox ./internal/xray

# Render every screen with the mockups' sample data, light and dark, to
# dist/snapshots/*.png (offscreen; needs no Screen Recording permission).
snapshots:
	swift build --package-path native
	rm -rf dist/snapshots
	native/.build/debug/XrayFriendly --snapshot dist/snapshots

# Swift unit tests (macOS only; Go tests stay in `make test`).
test-native:
	swift test --package-path native

clean:
	rm -rf bin dist native/.build
