all: bin/vmess

bin/vmess: $(shell find -name \*.rs) Cargo.toml
	@./build.sh
