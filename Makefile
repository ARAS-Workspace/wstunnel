TARGET_DIR  = ../Phantom-WG/Libraries/WstunnelKit
HEADER_SRC  = wstunnel-ios/include/wstunnel_ios.h

.PHONY: ios clean

ios:
	cargo build --release --target aarch64-apple-ios -p wstunnel-ios
	@mkdir -p $(TARGET_DIR)/include
	cp target/aarch64-apple-ios/release/libwstunnel_ios.a $(TARGET_DIR)/libwstunnel_ios.a
	cp $(HEADER_SRC) $(TARGET_DIR)/include/wstunnel_ios.h
	@echo "✓ libwstunnel_ios.a → $(TARGET_DIR)/"

clean:
	cargo clean
