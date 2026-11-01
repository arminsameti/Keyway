VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin/keywayd
# Separate path: go build refuses to overwrite a lipo'd fat binary.
UNIBIN  := bin/keywayd-universal

.PHONY: build vet lint smoke run app universal snapshots clean
build:
	@mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/keywayd
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/keyway-tun-helper ./cmd/keyway-tun-helper

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
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/xf-arm64 ./cmd/keywayd
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/xf-amd64 ./cmd/keywayd
	lipo -create -output $(UNIBIN) bin/xf-arm64 bin/xf-amd64
	rm -f bin/xf-arm64 bin/xf-amd64
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/xh-arm64 ./cmd/keyway-tun-helper
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/xh-amd64 ./cmd/keyway-tun-helper
	lipo -create -output bin/keyway-tun-helper-universal bin/xh-arm64 bin/xh-amd64
	rm -f bin/xh-arm64 bin/xh-amd64

# macOS app bundle: the SwiftUI app (universal) plus the universal Go backend.
APP         := dist/Keyway.app
SWIFT_BUILD := swift build -c release --package-path native --arch arm64 --arch x86_64
app: universal
	$(SWIFT_BUILD)
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp "$$($(SWIFT_BUILD) --show-bin-path)/Keyway" $(APP)/Contents/MacOS/Keyway
	cp $(UNIBIN) $(APP)/Contents/MacOS/keywayd
	cp bin/keyway-tun-helper-universal $(APP)/Contents/MacOS/keyway-tun-helper
	cp native/Info.plist $(APP)/Contents/Info.plist
	cp assets/icon.icns $(APP)/Contents/Resources/AppIcon.icns
	cp assets/logo.png $(APP)/Contents/Resources/Logo.png
	codesign --force --sign - $(APP)/Contents/MacOS/keywayd
	codesign --force --sign - $(APP)/Contents/MacOS/keyway-tun-helper
	codesign --force --sign - $(APP)/Contents/MacOS/Keyway
	codesign --force --sign - $(APP)
	codesign --verify --strict $(APP)

# Render every screen with the mockups' sample data, light and dark, to
# dist/snapshots/*.png (offscreen; needs no Screen Recording permission).
snapshots:
	swift build --package-path native
	rm -rf dist/snapshots
	native/.build/debug/Keyway --snapshot dist/snapshots

clean:
	rm -rf bin dist native/.build
