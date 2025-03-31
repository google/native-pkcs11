use std::{collections::HashMap, io::Write};

use goldenfile::Mint;

#[test]
fn test_pkcs11_tool() {
    let mut mint = Mint::new("tests/goldens/pkcs11-tool");
    let dylib_path = test_cdylib::build_current_project();

    let mut test_cases = HashMap::new();
    test_cases.insert("show_info", "--show-info");
    test_cases.insert("list_slots", "--list-slots");
    test_cases.insert("list_token_slots", "--list-token-slots");
    test_cases.insert("list_mechanisms", "--list-mechanisms");
    test_cases.insert("list_objects", "--list-objects");
    test_cases.insert("list_interfaces", "--list-interfaces");

    for (test_name, args) in test_cases {
        eprintln!("Running pkcs11-tool {}", test_name);
        let output = std::process::Command::new("pkcs11-tool")
            .arg("--module")
            .arg(&dylib_path)
            .arg(args)
            .output()
            .expect("Failed to execute pkcs11-tool");

        mint.new_goldenfile(format!("{}.stdout.txt", test_name))
            .unwrap()
            .write_all(&output.stdout)
            .unwrap();
        mint.new_goldenfile(format!("{}.stderr.txt", test_name))
            .unwrap()
            .write_all(&output.stderr)
            .unwrap();
    }
}
