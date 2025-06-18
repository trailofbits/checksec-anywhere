checksec_web:
	cd checksec.rs && wasm-pack build --target web --out-dir ../frontend/pkg

checksec:
	cd checksec.rs && cargo build --release

local_instance:
	cd frontend && python3 -m http.server

test:
	cd checksec.rs && cargo test

all: checksec_web checksec