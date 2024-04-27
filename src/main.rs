#![allow(unused)]

use std::future::IntoFuture;

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


async fn sqli_scan() {

}


#[tokio::main]
async fn main() {
    let args = Args::parse();

    // This prints out the url entered
    println!("URL to target: {:?}", args.target);

    let request_result = make_request(&args.target).await;

    let response = match request_result {
        Ok(response) => response,
        Err(error) => panic!("Problem with this request: {:?}", error),
    };

    println!("{:?}", response);

   find_forms(&response); 

   sqli_scan().await;


}

async fn make_request(url: &str) -> Result<String, reqwest::Error> {
    // make sure to use an exact url, not relative!
    let response = reqwest::get(url).await?;
    let body = response.text().await?;
    Ok(body)
}

fn find_forms(html_content: &str) {
    let document = Html::parse_document(html_content);
    let form_selector = Selector::parse("form").unwrap();
    let input_selector = Selector::parse("input").unwrap();
    // find each form on a page
    for form in document.select(&form_selector) {
        if let Some(action) = form.value().attrs().find(|(attr, _)| attr == &"action") {
            println!("Found form action: {}", action.1);
        } 
        if let Some(method) = form.value().attrs().find(|(attr, _)| attr == &"method") {
            println!("Found form method: {}", method.1);
        }
        
        // find all input tags in each form
        for input in form.select(&input_selector) {
            let name = input.value().attr("name").unwrap_or("no name");
            let input_type = input.value().attr("type").unwrap_or("no type");
            println!("Found input: type={} name={}", input_type, name);
        }
    }
}
