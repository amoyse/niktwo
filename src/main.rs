
use clap::Parser;
use reqwest::header::{HeaderValue, HeaderMap};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashMap;
use url::Url;
use serde_json;
use spider::tokio;
use spider::website::Website;
use tokio::sync::Semaphore;
use std::sync::Arc;


// may need to reference the clap docs for this
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {

    /// The target URL to scan for vulnerabilities (use a full url, including http(s)://)
    #[arg(short, long, value_name = "URL")]
    target: String,

    /// Scan as many pages that can be found associated with the given URL
    #[arg(long)]
    crawl: bool,

    /// Show all of the pages found by crawler before scanning
    #[arg(short, long)]
    verbose: bool,
}

// struct for storing information about an input tag associated with a form
#[derive(Debug)]
struct InputDetails {
    input_type: String,
    name: String,
    value: String
}

// struct for storing information about a form on a web page
#[derive(Debug)]
struct FormDetails {
    action: String,
    method: String,
    inputs: Vec<InputDetails>
}


// check for sql errors in response body
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


// perform the full sql injection scan on all the forms for a given url
async fn sqli_scan(forms: &Vec<FormDetails>, url: &str, client: &Client, is_crawling: &bool)  -> Result<(), Box<dyn std::error::Error>> {

    let payloads = vec![
        "\"",
        "'",
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 'x'='x",
    ];

    let mut is_vulnerable = false;

    for form in forms {
        for payload in &payloads {
            let mut data = HashMap::new();
            for input_tag in &form.inputs {

                // any input that is hidden or has value, use in form body with special char
                if input_tag.input_type == "hidden" || input_tag.value != "no value" {
                    let new_value = format!("{}{}", input_tag.value, payload);
                    data.insert(input_tag.name.to_string(), new_value);

                // any other input, use random data and special char
                } else if input_tag.input_type != "submit" {
                    let new_value = format!("test{}", payload);
                    data.insert(input_tag.name.to_string(), new_value);
                }
            }
            let new_url = Url::parse(url)?;
            let action_url = new_url.join(&form.action)?;

            if !["post", "get"].contains(&form.method.to_lowercase().as_str()) {
                if is_crawling.to_owned() {
                    break;
                } else {
                    println!("Unsupported form method.");
                    println!();
                    break;
                }
            }
            
            // .as_str() is needed to convert form.method from String to &str for matching with
            // "post" and "get"
            let response = match form.method.to_lowercase().as_str() {
                "post" => client.post(action_url).form(&data).send().await?,
                "get" => client.get(action_url).query(&data).send().await?,
                _ => unreachable!(),
            };
            if is_sqli_vulnerable(response.text().await?.to_lowercase()) {
                is_vulnerable = true;
                println!("[+] SQL Injection vulnerability detected on {} using {} payload", url, payload);
                println!("[*] Form: {:?}", form);
                println!();
                break;
            }
        }
    }
    if !is_vulnerable && !is_crawling {
        println!("[+] No SQL injection vulnerabilities detected.");
    }

    Ok(())
}

// perform a scan for xss vulnerabilities on all the forms on a given url
async fn xss_scan(forms: &Vec<FormDetails>, url: &str, client: &Client, is_crawling: &bool) -> Result<(), Box<dyn std::error::Error>> {

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

    let mut is_vulnerable = false;

    for form in forms {
        for payload in &xss_test_payloads {

            let new_url = Url::parse(url)?;
            let action_url = new_url.join(&form.action)?;
            let mut data = HashMap::new();

            for input in &form.inputs {

                if input.input_type == "submit" || (input.input_type == "radio" && input.value != "no value"){
                    continue;
                }
                let input_value = payload.to_string();

                if input.name != "no name" && input.value != "no value" {
                    data.insert(input.name.to_string(), input_value);
                }
            }
            if !["post", "get"].contains(&form.method.to_lowercase().as_str()) {
                if is_crawling.to_owned() {
                    break;
                } else {
                    println!("Unsupported form method.");
                    println!();
                    break;
                }
            }
            
            // .as_str() is needed to convert form.method from String to &str for matching with
            // "post" and "get"
            let response = match form.method.to_lowercase().as_str() {
                "post" => client.post(action_url).form(&data).send().await?,
                "get" => client.get(action_url).query(&data).send().await?,
                _ => unreachable!(),
            };

            let response_content = response.text().await?.to_lowercase();
            if response_content.contains(&payload.to_lowercase()) {
                is_vulnerable = true;
                println!("[+] XSS Detected on {}, using payload: {}", url, payload);
                println!("[*] Form details:");
                println!("{:?}", form);
                println!();
                break;
            }
        }
    }
    if !is_vulnerable && !is_crawling {
        println!("[+] No XSS vulnerabilities detected.");
    }
    Ok(())
}


// convert data of type HeaderMap to serde_json::Value for ease of use
fn convert(headers: &HeaderMap<HeaderValue>) -> serde_json::Value {
    format!("{:?}", headers).into()
}


// scan response headers to see if certain security headers are missing
async fn scan_security_headers(url: &str) -> Result<(), reqwest::Error> {
    let headers_to_check = vec![
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ];
    let response = reqwest::get(url).await?;
    let headers = response.headers();
    let headers_json = convert(headers);

    // retrieve the value for the server header, if it exists
    if let Some(server_value) = headers.get("Server") {

        // convert headervalue to a string if needed
        if let Ok(value_str) = server_value.to_str() {
            println!("[+] Server: {}", value_str);
        } else {
            println!("[+] Server header found, but contains invalid UTF-8");
        }
    } else {
        println!("[+] Server header not found");
    }

    for header in headers_to_check {
        if !headers_json.to_string().to_lowercase().contains(&header.to_lowercase()) {
            println!("[+] {} header is missing.", header);
        }
    }
    Ok(())
}


// start the different types of scans for the given url, passing the forms on the page
async fn start_scan(target_url: &str, client: &Client, is_crawling: &bool) -> Result<(), Box<dyn std::error::Error>> {


    let response = match make_request(&target_url).await {
        Ok(response) => response,
        Err(e) => {
            if e.is_builder() {
                println!("URL parsing error: {}", e);
            } else if e.is_connect() {
                println!("Connection error: {}", e);
            } else if e.is_request() {
                println!("Request error: {}", e);
            } else if e.is_timeout() {
                println!("Timeout error: {}", e);
            } else {
                println!("An error occurred: {}", e);
            }
            return Err(Box::new(e));
        }
    };

    let forms = find_forms(&response);

    // if scanning crawled pages, don't perform a security header scan on every page
    if is_crawling.to_owned() {
        let _ = sqli_scan(&forms, target_url, client, is_crawling).await;
        let _ = xss_scan(&forms, target_url, client, is_crawling).await;

    } else {
        println!();
        let _ = scan_security_headers(target_url).await;

        println!();
        println!("[+] Detected {} forms on {}.", forms.len(), target_url);

        println!();
        let _ = sqli_scan(&forms, target_url, client, is_crawling).await;
        println!();
        let _ = xss_scan(&forms, target_url, client, is_crawling).await;
    }

    Ok(())
}



#[tokio::main]
async fn main() {
    let args = Args::parse();
    let target_url = args.target;
    let is_crawling = args.crawl;

    let client = Client::new();
    println!();

    if is_crawling {
        let mut website: Website = Website::new(&target_url);
        website.crawl().await;
        let links = website.get_links();

        match scan_security_headers(&target_url).await {
            Ok(()) => {},
            Err(e) => {
                if e.is_builder() {
                    println!("URL parsing error: {}", e);
                } else if e.is_connect() {
                    println!("Connection error: {}", e);
                } else if e.is_request() {
                    println!("Request error: {}", e);
                } else if e.is_timeout() {
                    println!("Timeout error: {}", e);
                } else {
                    println!("An error occurred: {}", e);
                }
                return;
            }
        }
        println!();

        // create a new semaphore with a max thread count of 5
        let max_concurrency = 5;
        let semaphore = Arc::new(Semaphore::new(max_concurrency));

        let mut handles = Vec::new();

        if args.verbose {
            println!("[+] Pages to scan:");
            for link in links {
                println!("- {:?}", link.as_ref());
            }
            println!();
        }

        for link in links.clone() {
            let client_clone = client.clone();

            // get a permit from the semaphore
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(e) => {
                    eprintln!("Failed to acquire a semaphore permit: {:?}", e);
                    return;
                }
            };
            let handle = tokio::spawn(async move {
                let _ = start_scan(link.as_ref(), &client_clone, &is_crawling).await;

                // give permit back to semaphore for next task
                drop(permit);
            });
            handles.push(handle);
        }

        // wait for all tasks to finish after spawned
        for handle in handles {
            match handle.await {
                Ok(_) => {},
                Err(e) => eprintln!("One thread had an error: {}", e),
            }
        }

    } else {
        println!("URL to target: {:?}", target_url);
        let _ = start_scan(&target_url, &client, &is_crawling).await;
    }
    println!();
    println!("Scan finished");

}


// make a request to the server and return reponse body
async fn make_request(url: &str) -> Result<String, reqwest::Error> {
    let response = reqwest::get(url).await?;
    let body = response.text().await?;
    Ok(body)
}


// parse html content to find forms on a page, and return vector of FormDetails
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
