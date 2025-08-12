wasm:
	wasm-pack build checksec-wasm --target web --out-dir ../frontend/pkg --out-name checksec

cli:
	cargo build -p checksec --bin checksec --release

local_instance: wasm
	cd frontend && python3 -m http.server

test:
	cargo test -p checksec

clean:
	cargo clean
	rm -rf frontend/pkg
	rm -rf checksec-wasm/pkg

all: wasm cli