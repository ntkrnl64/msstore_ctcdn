fn main() {
    #[cfg(target_os = "windows")]
    embed_resource::compile("msstore_ctcdn.rc", embed_resource::NONE);
}
