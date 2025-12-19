use zsync_core::Scanner;
use std::path::PathBuf;

fn main() {
    let scanner = Scanner::new("/Users/andrewgazelka/Projects/greenfield");
    let entries = scanner.scan().unwrap();

    // Check for target files
    let target_files: Vec<_> = entries.iter()
        .filter(|e| e.path.starts_with("target"))
        .collect();

    println!("Total files: {}", entries.len());
    println!("Target files: {}", target_files.len());

    if !target_files.is_empty() {
        println!("\nSample target files:");
        for f in target_files.iter().take(10) {
            println!("  {}", f.path.display());
        }
    }
}
