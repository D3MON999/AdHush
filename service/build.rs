// Embeds the AdHush icon and version info (installer/adhush.rc) into the executable.
fn main() {
    println!("cargo:rerun-if-changed=../installer/adhush.rc");
    println!("cargo:rerun-if-changed=../installer/adhush.ico");
    embed_resource::compile("../installer/adhush.rc", embed_resource::NONE).manifest_optional().unwrap();
}
