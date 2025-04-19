use cipher::AppError;
use std::env;

fn main() -> Result<(), AppError> {
    let mut args = env::args();
    let command = args
        .nth(1)
        .ok_or_else(|| AppError::from_str("usage", "missing command"))?;
    let input_file = args
        .nth(0)
        .ok_or_else(|| AppError::from_str("usage", "missing file name"))?;
    let output_file = args.nth(3).unwrap_or_else(|| input_file.clone());

    if command.as_str() == "cat" {
        cipher::cat_command(&input_file)
    } else {
        Err(AppError::from_str(
            "usage",
            format!("invalid command: {}", command.as_str()).as_str(),
        ))
    }
}
