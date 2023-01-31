import re
from urllib.parse import urlparse
import os.path
from bs4 import BeautifulSoup
from collections import defaultdict

class Our_Scraper():
    def __init__(self):
        # Stores all of the tokens for the pages we visit
        self.token_dict = defaultdict(int)

        # After we tokenize ??? pages, we will write our token_dict to a log file
        self.counter = 0

        # This is our log file that we will write to
        self.logger = get_logger("Token-Dictionary", "Token_Dict")

    def scraper(self, url, resp):
        links = extract_next_links(url, resp)
        return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    # NOTE: this currently runs for a while and must be stopped with a keyboard interrupt (ctrl+C)
    hyperlinks = set()  # will be returned at end of function
    if (resp and resp.status == 200 and resp.raw_response and resp.raw_response.content):
        # if there is a response and if that response has content, parse it
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
        for link in soup.find_all('a'):
            # grab all urls from page's <a> tags using beautiful soup
            url = link.get('href')
            #check if url is relative 
            #print("url before check", url)
            if not check_if_absolute(url):
                #convert to absolute url
                print("relative url", url)
                #change_url_to_absolute(url, resp.url)
            if is_valid(url) and (url not in hyperlinks):
                # if url is valid, try to defragment it (remove everything after the # character)
                # url will remain unchanged if it is not fragmented
                url = re.sub(r"#.*$", "", url)
                # add url to hyperlinks
                hyperlinks.add(url)
                print(url)
    return list(hyperlinks)

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        return re.match(r"(.+?\.)?(ics|cs|informatics|stat)\.uci\.edu", parsed.netloc) and not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$"
            + r"|#", parsed.path.lower())
    except TypeError:
        print ("TypeError for ", parsed)
        raise

def check_if_absolute(url):
    #returns true if url is absolute, netloc != '' 
    #returns false if url is relative
    #add additional checks to check for / ./ ../
    #Note: check for '/' first (use regex)
    return bool(urlparse(url).netloc)

def change_url_to_absolute(url):
    #make sure it is relative
    #whenerv u encounter relativee links just appebd it to the actual url of the page by resp.url
    #url = link.get 
    pass
