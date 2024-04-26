#![allow(unused)]

use clap::Parser;
use reqwest::Error;
use scraper::{Html, Selector};


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
    println!("URL to target: {:?}", args.target);

    let request_result = make_request(&args.target);

    let response = match request_result {
        Ok(response) => response,
        Err(error) => panic!("Problem with this request: {:?}", error),
    };

    println!("{:?}", response);

   find_forms(&response); 
}

fn make_request(url: &str) -> Result<String, Error> {
    // make sure to use an exact url, not relative!
    let response = reqwest::blocking::get(url)?;
    response.text()
}

fn find_forms(html_content: &str) {
    let document = Html::parse_document(html_content);
    let selector = Selector::parse("form").unwrap();
    for element in document.select(&selector) {
        println!("Found form: {:?}", element.value());
    }
}
