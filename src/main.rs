use cipher::app;
use cipher::app::AppError;
use cipher::encryption;
use std::env;

fn main() -> Result<(), AppError> {
    let mut args = env::args();
    let command = args
        .nth(1)
        .ok_or_else(|| AppError::from_str("usage", "missing command"))?;
    let input_file = args
        .next()
        .ok_or_else(|| AppError::from_str("usage", "missing file name"))?;
    let output_file = args.next().unwrap_or_else(|| input_file.clone());

    let encryption_system = encryption::new_insecure_encryption()?;
    if command.as_str() == "cat" {
        app::cat_command(&input_file, encryption_system.as_ref())
    } else if command.as_str() == "decrypt" {
        if input_file == output_file {
            return Err(AppError::from_str(
                "usage",
                "decrypt requires an output file name",
            ));
        }
        app::decrypt_command(&input_file, &output_file, encryption_system.as_ref())
    } else if command.as_str() == "encrypt" {
        app::encrypt_command(&input_file, &output_file, encryption_system.as_ref())
    } else if command.as_str() == "rewind" {
        app::rewind_command(&input_file, &output_file, encryption_system.as_ref())
    } else if command.as_str() == "edit" {
        app::edit_command(&input_file, &output_file, encryption_system.as_ref())
    } else {
        Err(AppError::from_str(
            "usage",
            format!("invalid command: {}", command.as_str()).as_str(),
        ))
    }
}
