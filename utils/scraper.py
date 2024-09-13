import requests
from bs4 import BeautifulSoup

# Define a function to scrape the text content from a URL
def scrape_url(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url)
        
        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
            
        # Extract the relevant text content from the HTML
        text = soup.get_text()
        # Preprocess the text content as needed

        processed_text = preprocess_text(text)
        print(processed_text)
        return processed_text
    except Exception as e:
        print(str(e))
        return False

# Define a function to preprocess the extracted text content
def preprocess_text(text):
    # Clean the text by removing unwanted characters and symbols
    cleaned_text = text.replace('\n', ' ').replace('\r', '').strip()
    return cleaned_text


# Scrape the text content from each URL and store it in a list
def scrape_urls(urls):    
    # Scrape the text content from each URL
    scraped_data = []
    try:
        for url in urls:
            scraped_text = scrape_url(url)
            if scraped_text is False:
                return False
            scraped_data.append(scraped_text)
        return scraped_data
    except:
        return False






