use cipher::AppError;
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

    if command.as_str() == "cat" {
        cipher::cat_command(&input_file)
    } else if command.as_str() == "decrypt" {
        if input_file == output_file {
            return Err(AppError::from_str(
                "usage",
                "decrypt requires an output file name",
            ));
        }
        cipher::decrypt_command(&input_file, &output_file)
    } else if command.as_str() == "encrypt" {
        cipher::encrypt_command(&input_file, &output_file)
    } else if command.as_str() == "rewind" {
        cipher::rewind_command(&input_file, &output_file)
    } else if command.as_str() == "edit" {
        cipher::edit_command(&input_file, &output_file)
    } else {
        Err(AppError::from_str(
            "usage",
            format!("invalid command: {}", command.as_str()).as_str(),
        ))
    }
}
