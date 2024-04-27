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

#[derive(Debug)]
struct InputDetails {
    input_type: String,
    name: String,
}

#[derive(Debug)]
struct FormDetails {
    action: Option<String>,
    method: Option<String>,
    inputs: Vec<InputDetails>
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

   println!("{:?}", find_forms(&response));

   sqli_scan().await;


}

async fn make_request(url: &str) -> Result<String, reqwest::Error> {
    // make sure to use an exact url, not relative!
    let response = reqwest::get(url).await?;
    let body = response.text().await?;
    Ok(body)
}

fn find_forms(html_content: &str) -> Vec<FormDetails> {
    let document = Html::parse_document(html_content);
    let form_selector = Selector::parse("form").unwrap();
    let input_selector = Selector::parse("input").unwrap();

    let mut all_form_details: Vec<FormDetails> = Vec::new();

    // find each form on a page
    for form in document.select(&form_selector) {
        let mut form_info = FormDetails {
            action: None,
            method: None,
            inputs: Vec::new(),
        };

        if let Some(action) = form.value().attr("action") {
            form_info.action = Some(action.to_string());
            println!("Found form action: {}", action);
        } 
        if let Some(method) = form.value().attr("method") {
            form_info.method = Some(method.to_string());
            println!("Found form method: {}", method);
        } 
        
        // find all input tags in each form
        for input in form.select(&input_selector) {
            let name = input.value().attr("name").unwrap_or("no name").to_string();
            let input_type = input.value().attr("type").unwrap_or("no type").to_string();
            println!("Found input: type={} name={}", input_type, name);

            // Add the found input details to the form_info.inputs vector
            form_info.inputs.push(InputDetails {
                input_type,
                name,
            });
        }
        all_form_details.push(form_info);
    }
    all_form_details
}
