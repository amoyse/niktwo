#![allow(unused)]

use core::panic;
use std::future::IntoFuture;

use clap::Parser;
use reqwest::header::{HeaderValue, HeaderMap};
use reqwest::{Client, Error};
use scraper::{Html, Selector};
use std::collections::HashMap;
use url::Url;
use serde_json;


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

    // may need to add in more test payloads
    // also maybe call this variable test_payloads
    let chars = vec!['"', '\''];

    let mut is_vulnerable = false;

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
            if is_sqli_vulnerable(response.text().await?.to_lowercase()) {
                is_vulnerable = true;
                println!("[+] SQL Injection vulnerability detected, link: {}", url);
                println!("[+] Form: {:?}", form);
            }
        }
    }
    if !is_vulnerable {
        println!("[+] No SQL injection vulnerabilities detected.");
    }

    Ok(())
}

async fn xss_scan(forms: &Vec<FormDetails>, url: &str) -> Result<(), Box<dyn std::error::Error>> {

    let js_script = String::from("<script>alert('hi')</script>");
    let mut is_vulnerable = false;

    let xss_test_payloads = vec![
        "<script>alert('XSS')</script>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        r#"<img src='x' onerror=%22alert('XSS')%22>"#,
        "<script>/*<!--*/alert('XSS')//-->*/</script>",
        "<svg/onload=alert('XSS')>",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
        r#"<style>@import 'javascript:alert("XSS")';</style>"#
    ];

    for form in forms {
        for payload in &xss_test_payloads {

            let new_url = Url::parse(url).unwrap();
            let action_url = new_url.join(&form.action).unwrap();
            let client = Client::new();
            let mut data = HashMap::new();

            for input in &form.inputs {
                let mut input_value = String::new(); 

                if input.input_type == "submit" || (input.input_type == "radio" && input.value != "no value"){
                    continue;
                }
                input_value = payload.to_string();

                if input.name != "no name" && input.value != "no value" {
                    data.insert(input.name.to_string(), input_value);
                }
            }
            let response = match form.method.to_lowercase().as_str() {
                "post" => client.post(action_url).form(&data).send().await?,
                "get" => client.get(action_url).query(&data).send().await?,
                "no method" => client.get(action_url).query(&data).send().await?,
                _ => panic!("Unsupported form method.")
            };
            let response_content = response.text().await?.to_lowercase();
            // println!("{}", payload);
            // println!("Response:");
            // println!("{:?}", response_content);
            if response_content.contains(&payload.to_lowercase()) {
                is_vulnerable = true;
                println!("\n[+] XSS Detected on {}, using payload: {}", url, payload);
                println!("[*] Form details:");
                println!("{:?}", form);
                println!();
                break;
            }
        }
    }
    if !is_vulnerable {
        println!("[+] No XSS vulnerabilities detected.");
    }
    Ok(())
}

fn convert(headers: &HeaderMap<HeaderValue>) -> serde_json::Value {
    format!("{:?}", headers).into()
}

async fn scan_security_headers(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let headers_to_check = vec![
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ];
    let response = reqwest::get(url).await?;
    let headers = response.headers();
    let headers_json = convert(headers);

    for header in headers_to_check {
        if !headers_json.to_string().to_lowercase().contains(&header.to_lowercase()) {
            println!("{} header is missing.", header);
        }
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

    // println!("{:?}", response);


    println!();
    scan_security_headers(&target_url).await;

    println!();
    let forms = find_forms(&response);
    println!("[+] Detected {} forms on {}.", &forms.len(), &target_url);

    println!();
    sqli_scan(&forms, &target_url).await;
    println!();
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
        form_info.action = action;
        form_info.method = method;
        
        // find all input tags in each form
        for input in form.select(&input_selector) {
            let name = input.value().attr("name").unwrap_or("no name").to_string();
            let input_type = input.value().attr("type").unwrap_or("no type").to_string();
            let value = input.value().attr("value").unwrap_or("no value").to_string();
            // println!("Found input: type={} name={} value={}", input_type, name, value);

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
