all:
	cd checksec.rs && wasm-pack build --target web --out-dir ../frontend/pkg

test:
	cd checksec.rs && cargo test