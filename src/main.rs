#![allow(unused)]

use core::panic;
use std::future::IntoFuture;

use clap::Parser;
use reqwest::{Client, Error};
use scraper::{Html, Selector};
use std::collections::HashMap;
use url::Url;


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
    value: String
}

#[derive(Debug)]
struct FormDetails {
    action: String,
    method: String,
    inputs: Vec<InputDetails>
}

fn is_sqli_vulnerable(response: String) -> bool {
    let errors = vec![
        "you have an error in your sql syntax;", 
        "warning: mysql", 
        "unclosed quotation mark after the character string", 
        "quoted string not properly terminated"
    ];

    for error in errors {
        if response.contains(error) {
            return true;
        }
    }
    false
}

async fn sqli_scan(forms: &Vec<FormDetails>, url: &str)  -> Result<(), Box<dyn std::error::Error>> {
    println!("[+] Detected {} forms on {}.", forms.len(), url);

    // may need to add in more test payloads
    // also maybe call this variable test_payloads
    let chars = vec!['"', '\''];


    for form in forms {
        for c in &chars {
            let mut data = HashMap::new();
            for input_tag in &form.inputs {

                // any input that is hidden or has value, use in form body with special char
                if input_tag.input_type == "hidden" || input_tag.value != "no value" {
                    let new_value = format!("{}{}", input_tag.value, c);
                    data.insert(input_tag.name.to_string(), new_value);

                // any other input, use random data and special char
                } else if input_tag.input_type != "submit" {
                    let new_value = format!("test{}", c);
                    data.insert(input_tag.name.to_string(), new_value);
                }
            }
            let new_url = Url::parse(url).unwrap();
            let action_url = new_url.join(&form.action).unwrap();
            
            let client = Client::new();

            // .as_str() is needed to convert form.method from String to &str for matching with
            // "post" and "get"
            let response = match form.method.to_lowercase().as_str() {
                "post" => client.post(action_url).form(&data).send().await?,
                "get" => client.get(action_url).query(&data).send().await?,
                _ => panic!("Unsupported form method.")
            };
            println!("{:?}", response);
            if is_sqli_vulnerable(response.text().await?.to_lowercase()) {
                println!("[+] SQL Injection vulnerability detected, link: {}", url);
                println!("[+] Form: {:?}", form);
            }
        }
    }
    Ok(())
}

async fn xss_scan(forms: &Vec<FormDetails>, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let js_script = String::from("<script>alert('hi')</script>");

    for form in forms {
        let new_url = Url::parse(url).unwrap();
        let action_url = new_url.join(&form.action).unwrap();
        let client = Client::new();
        let mut data = HashMap::new();
        
        for input in &form.inputs {
            let mut input_value = String::new(); 
            if input.input_type == "text" || input.input_type == "search" {
                input_value = js_script.clone();
            }
            else {
                input_value = input.value.clone();
            }
            if input.name != "no name" && input.value != "no value" {
                data.insert(input.name.to_string(), input_value);
            }
        }
        let response = match form.method.to_lowercase().as_str() {
            "post" => client.post(action_url).form(&data).send().await?,
            "get" => client.get(action_url).query(&data).send().await?,
            _ => panic!("Unsupported form method.")
        };
        println!("{:?}", response.text().await?.to_lowercase());


    }

    Ok(())
}


#[tokio::main]
async fn main() {
    let args = Args::parse();
    let target_url = args.target;

    // This prints out the url entered
    println!("URL to target: {:?}", target_url);

    let request_result = make_request(&target_url).await;

    let response = match request_result {
        Ok(response) => response,
        Err(error) => panic!("Problem with this request: {:?}", error),
    };

    println!("{:?}", response);

    let forms = find_forms(&response);
    println!("{:?}", forms);

    // sqli_scan(&forms, &target_url).await;
    xss_scan(&forms, &target_url).await;


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
            action: String::new(),
            method: String::new(),
            inputs: Vec::new(),
        };

        let action = form.value().attr("action").unwrap_or("no action").to_string();
        let method = form.value().attr("method").unwrap_or("no method").to_string();
        println!("Found form action: {}", action);
        println!("Found form method: {}", method);
        form_info.action = action;
        form_info.method = method;
        
        // find all input tags in each form
        for input in form.select(&input_selector) {
            let name = input.value().attr("name").unwrap_or("no name").to_string();
            let input_type = input.value().attr("type").unwrap_or("no type").to_string();
            let value = input.value().attr("value").unwrap_or("no value").to_string();
            println!("Found input: type={} name={} value={}", input_type, name, value);

            // add the found input details to the form_info.inputs vector
            form_info.inputs.push(InputDetails {
                input_type,
                name,
                value,
            });
        }
        all_form_details.push(form_info);
    }
    all_form_details
}
