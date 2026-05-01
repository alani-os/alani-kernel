#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_kernel::repository_name(), "alani-kernel");
    assert!(!alani_kernel::module_names().is_empty());
}
