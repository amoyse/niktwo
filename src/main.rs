use clap::Parser;
use reqwest::Error;


// may need to reference the clap docs for this
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    target: String,

    #[arg(long, action)]
    ssl: bool,
}

fn main() {
    let args = Args::parse();

    // This prints out the url entered
    println!("{:?}", args.target);

    let response = make_request(&args.target);
    println!("{:?}", response);

    
}

fn make_request(url: &str) -> Result<String, Error> {
    let response = reqwest::blocking::get(url)?;
    response.text()
}
