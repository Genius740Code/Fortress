fn main() {
    println!("cargo:rerun-if-changed=proto/fortress.proto");
    // Note: protobuf compilation requires protoc to be installed
    // For now, we use tonic::include_proto! which handles this at compile time
}
