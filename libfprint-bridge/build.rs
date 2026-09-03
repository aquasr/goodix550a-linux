fn main() {
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libgoodix550a_bridge.so");
}
