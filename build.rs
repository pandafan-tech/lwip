use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn sdk_path_for(sdk: &str) -> String {
    // sdk path find by `xcrun --sdk {iphoneos|macosx} --show-sdk-path`
    let output = Command::new("xcrun")
        .arg("--sdk")
        .arg(sdk)
        .arg("--show-sdk-path")
        .output()
        .expect("failed to execute xcrun");

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn sdk_include_path_for(sdk: &str) -> String {
    let sdk_path = sdk_path_for(sdk);
    let inc_path = Path::new(&sdk_path).join("usr/include");
    inc_path.to_str().expect("invalid include path").to_string()
}

fn sdk_include_path() -> Option<String> {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target = env::var("TARGET").unwrap();
    match os.as_str() {
        "ios" => {
            if arch == "x86_64" || target.ends_with("-sim") {
                Some(sdk_include_path_for("iphonesimulator"))
            } else {
                Some(sdk_include_path_for("iphoneos"))
            }
        }
        "tvos" => {
            if target.ends_with("-sim") {
                Some(sdk_include_path_for("appletvsimulator"))
            } else {
                Some(sdk_include_path_for("appletvos"))
            }
        }
        "macos" => Some(sdk_include_path_for("macosx")),
        _ => None,
    }
}

fn apple_clang_target() -> Option<String> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let arch = match arch.as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        _ => return None,
    };
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target = env::var("TARGET").unwrap();
    let simulator = target.ends_with("-sim");
    let (platform, deployment_target) = match os.as_str() {
        "ios" => (
            "ios",
            env::var("IPHONEOS_DEPLOYMENT_TARGET")
                .expect("IPHONEOS_DEPLOYMENT_TARGET must be set for iOS builds"),
        ),
        "tvos" => (
            "tvos",
            env::var("TVOS_DEPLOYMENT_TARGET")
                .expect("TVOS_DEPLOYMENT_TARGET must be set for tvOS builds"),
        ),
        _ => return None,
    };

    Some(format!(
        "{arch}-apple-{platform}{deployment_target}{}",
        if simulator { "-simulator" } else { "" }
    ))
}

fn compile_lwip() {
    println!("cargo:rerun-if-changed=src/core");
    println!("cargo:rerun-if-changed=src/include");
    println!("cargo:rerun-if-changed=port");
    let mut build = cc::Build::new();
    build
        .file("src/core/init.c")
        .file("src/core/def.c")
        // .file("src/core/dns.c")
        .file("src/core/inet_chksum.c")
        .file("src/core/ip.c")
        .file("src/core/mem.c")
        .file("src/core/memp.c")
        .file("src/core/netif.c")
        .file("src/core/pbuf.c")
        .file("src/core/raw.c")
        // .file("src/core/stats.c")
        // .file("src/core/sys.c")
        .file("src/core/tcp.c")
        .file("src/core/tcp_in.c")
        .file("src/core/tcp_out.c")
        .file("src/core/timeouts.c")
        .file("src/core/udp.c")
        .file("src/core/ipv4/acd.c")
        // .file("src/core/ipv4/autoip.c")
        // .file("src/core/ipv4/dhcp.c")
        // .file("src/core/ipv4/etharp.c")
        .file("src/core/ipv4/icmp.c")
        // .file("src/core/ipv4/igmp.c")
        .file("src/core/ipv4/ip4_frag.c")
        .file("src/core/ipv4/ip4.c")
        .file("src/core/ipv4/ip4_addr.c")
        // .file("src/core/ipv6/dhcp6.c")
        // .file("src/core/ipv6/ethip6.c")
        .file("src/core/ipv6/icmp6.c")
        // .file("src/core/ipv6/inet6.c")
        .file("src/core/ipv6/ip6.c")
        .file("src/core/ipv6/ip6_addr.c")
        .file("src/core/ipv6/ip6_frag.c")
        // .file("src/core/ipv6/mld6.c")
        .file("src/core/ipv6/nd6.c")
        .file("port/sys_arch.c")
        .file("port/rust_accessors.c")
        .file("src/api/err.c")
        .include("port")
        .include("src/include")
        .warnings(false)
        .flag_if_supported("-Wno-everything");
    if let Some(sdk_include_path) = sdk_include_path() {
        build.include(sdk_include_path);
    }
    let target = env::var("TARGET").unwrap();
    if target == "aarch64-apple-tvos-sim" {
        let clang_target = apple_clang_target().unwrap();
        build
            .target("aarch64-apple-tvos")
            .flag(&format!("--target={clang_target}"))
            .flag("-isysroot")
            .flag(&sdk_path_for("appletvsimulator"));
    }
    build.debug(true);
    build.compile("liblwip.a");
}

fn generate_lwip_bindings() {
    println!("cargo:rustc-link-lib=lwip");
    println!("cargo:include=src/include");

    let sdk_include_path = sdk_include_path();

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let mut builder = bindgen::Builder::default()
        .header("port/wrapper.h")
        .clang_arg("-I./src/include")
        .clang_arg("-I./port")
        .clang_arg("-Wno-everything")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    if let Some(target) = apple_clang_target() {
        // https://github.com/rust-lang/rust-bindgen/issues/1211
        builder = builder.clang_arg(format!("--target={target}"));
    }
    if let Some(sdk_include_path) = sdk_include_path {
        builder = builder.clang_arg(format!("-I{}", sdk_include_path));
    }

    if os == "windows" {
        builder = builder.size_t_is_usize(false);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    compile_lwip();
    generate_lwip_bindings();
    println!("cargo:rerun-if-changed=build.rs");
}
