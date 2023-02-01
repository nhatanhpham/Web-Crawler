import re
from urllib.parse import urlparse
from urllib.parse import urljoin
from utils import get_logger
import os.path
from bs4 import BeautifulSoup
from collections import defaultdict
import nltk
from nltk.tokenize import word_tokenize
import pickle
import sys
#nltk.download('punkt')

class Our_Scraper:
    def __init__(self):
        # Instead of using nltk stopwords, we used the exact stopwords given in the assignment
        self.stop_words = Our_Scraper.generate_stop_words()

        # Stores all of the tokens for the pages we visit
        self.token_dict = defaultdict(int)

        # Defines the name of our pickle file to store all the token dictionaries
        self.pickle_name = "Dicts_Storage"

        # Keeps track of how many unique pages we found
        self.pages = 0

        # After we tokenize ??? pages, we will write our token_dict to a log file
        self.counter = 0

        # Keeps track of the longest page in terms of the # of words
        self.max_words = 0
        self.max_page = ''

        # This are the regular expressions to validate the subdomains of ics.uci.edu
        self.subdomain_good = re.compile(r".+//.+\.ics\.uci\.edu")
        self.subdomain_ignore = re.compile(r".+//www\.ics\.uci\.edu")

        # This dictionary keeps track of the subdomains and the count of their pages
        self.subdomains = defaultdict(int)

    def scraper(self, url, resp):
        # We found another unique page, even if we don't crawl it
        self.pages += 1

        self.check_subdomain(url)

        # If we have seen over 100 pages, write our token dict to logs and then reset it
        if self.counter > 100:
            self.add_to_pickle()

        # We also do this checking in the extract_next_links function, I think one of them should not duplicate this
        if (resp and resp.status == 200 and resp.raw_response and resp.raw_response.content):
            soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
            text = soup.get_text()
            
            whitespace = text.count('\n') + text.count(' ') + text.count('\v') 
            + text.count('\t') + text.count('\r') + text.count('\f')

            #if len(soup.get_text()) - whitespace < 400:
                #print("***TEXT SIZE***", len(soup.get_text()), len(soup.get_text()) - whitespace, soup.get_text(), resp.raw_response.content)

            # We need to change this to only crawl good pages that meet our criteria
            #Crawl all pages with high textual information content > 400 characters excluding whitespace
            if len(soup.get_text()) - whitespace > 400:
                # Extract all the text from the page into tokens
                self.counter += 1
                tokens = word_tokenize(soup.get_text())
                word_count = 0

                for token in tokens:
                    # make sure work is just not a symbol before counting it and adding to self.token_dict
                    if (not re.match(r"^(\W|_)+$", token)):
                    # Keep track of how many words this page has, regardless of it is a stopword
                        word_count += 1

                        token = token.casefold()
                        if token not in self.stop_words:
                            self.token_dict[token] += 1
                
                if word_count > self.max_words:
                    self.max_words = word_count
                    self.max_page = url

                # Add a portion to keep track/count subdomain pages

                links = extract_next_links(url, resp, soup)
                return links
        return []

    @staticmethod 
    def generate_stop_words():
        input_path = "Stop_Words.txt"
        input_file = open(input_path, 'r')

        stop_words = set()
        for word in input_file:
            stop_words.add(word[:-1])

        input_file.close()

        return stop_words

    # Dumps the current token_dict to the pickle file
    # Also it clears the token_dict and sets the counter to 0
    def add_to_pickle(self):
        with open(self.pickle_name, 'a+b') as pickle_file:
            pickle.dump(self.token_dict, pickle_file)

        self.token_dict.clear()
        self.counter = 0

    # Returns all of the dictionaries from the pickle file
    def read_from_pickle(self):
        with open(self.pickle_name, 'rb') as pickle_file:
            while True:
                try:
                    yield pickle.load(pickle_file)
                except EOFError:
                    break

    # This checks if the given url is a subdomain of "ics.uci.edu", and if it is add 1 to the page
    # count for that subdomain
    def check_subdomain(self, url):
        match = self.subdomain_good.match(url)

        if match and not self.subdomain_ignore.match(url):
            self.subdomains[match.group(0)] += 1

    # This loads all of the dictionaries from the pickle file, makes one large dictionary 
    # of the frequency of each token, sorts it, and then returns the keys
    def make_freq_dict(self):
        total_token_dict = defaultdict(int)
        
        for token_dict in self.read_from_pickle():
            for token, freq in token_dict.items():
                total_token_dict[token] += freq

        for token, _ in sorted(total_token_dict.items(), key = (lambda item : (-item[1], item[0]))):
            yield token

    # This gathers all of the data and prints out the report to the file named "Report.txt"
    def make_report(self):
        std_stdout = sys.stdout
        with open("Report.txt", 'w') as report:
            sys.stdout = report
            print(f"1. We found {self.pages} unique pages\n")
            print(f"2. The longest page in terms of the number of words is {self.max_page}\n")

            print("3. The 50 most common words in the entire set of pages crawled under these domains are:")
            counter = 50
            for word in self.make_freq_dict():
                if counter <= 0:
                    break
                print(word)
                counter -= 1
            
            print(f"\n4. We found {len(self.subdomains)} in the ics.uci.edu domain.\n")

            for subdomain, freq in sorted(self.subdomains.items(), key = (lambda item : (item[0], -item[1]))):
                print(f"{subdomain}, {freq}")

        sys.stdout = std_stdout


def extract_next_links(url, resp, soup):
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
    for link in soup.find_all('a'):
        # grab all urls from page's <a> tags using beautiful soup
        url = link.get('href')

        #check if url is relative 
        #if url is not None and check_if_relative(url):
            #url = change_url_to_absolute(url, resp)
        if is_valid(url) and (url not in hyperlinks):
            # if url is valid, try to defragment it (remove everything after the # character)
            # url will remain unchanged if it is not fragmented
            url = re.sub(r"#.*$", "", url)
            # add url to hyperlinks
            hyperlinks.add(url)
            #print(url)
    return list(hyperlinks)

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        #TO-DO: check url for calendar or uploads
        return re.match(r"(.+?\.)?(ics|cs|informatics|stat)\.uci\.edu", parsed.netloc) and not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz|apk)$"
            + r"|#", parsed.path.lower())
    except TypeError:
        print ("TypeError for ", parsed)
        raise

def check_if_relative(url):
    return bool(re.match(r'^[.]*[\/].+$', url))

#TO-DO: parse resp.url for only til the end of authority and take care of other cases outside of /
def change_url_to_absolute(url, resp):
    return urljoin(resp.url, url)



