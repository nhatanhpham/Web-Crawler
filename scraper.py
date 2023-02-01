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

        # This is our log file that we will write to
        self.logger = get_logger("Token-Dictionary", "Token_Dict")

    def scraper(self, url, resp):
        # We found another unique page, even if we don't crawl it
        self.pages += 1

        # If we have seen over ??? pages, write our token dict to logs and then reset it
        self.counter += 1
        if self.counter > 100:
            self.Add_To_Pickle(self.token_dict)
            self.token_dict.clear()
            self.counter = 0

        if (resp and resp.status == 200 and resp.raw_response and resp.raw_response.content):
            soup = BeautifulSoup(resp.raw_response.content, 'html.parser')

            whitespace = soup.get_text().count('\n') + soup.get_text().count(' ') + soup.get_text().count('\v') 
            + soup.get_text().count('\t') + soup.get_text().count('\r') + soup.get_text().count('\f')

            #if len(soup.get_text()) - whitespace < 400:
                #print("***TEXT SIZE***", len(soup.get_text()), len(soup.get_text()) - whitespace, soup.get_text(), resp.raw_response.content)

            # We need to change this to only crawl good pages that meet our criteria
            #Crawl all pages with high textual information content > 400 characters excluding whitespace
            if len(soup.get_text()) - whitespace > 400:
                # Extract all the text from the page into tokens
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

                # Add a portion to keep track/count subdomain pages

                links = extract_next_links(url, resp)
                return [link for link in links if is_valid(link)]
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

    def Add_To_Pickle(self, dictionary):
        with open(self.pickle_name, 'a+b') as pickle_file:
            pickle.dump(dictionary, pickle_file)

    def Read_From_Pickle(self):
        with open(self.pickle_name, 'rb') as pickle_file:
            while True:
                try:
                    yield pickle.load(pickle_file)
                except EOFError:
                    break
    

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
            if url is not None and check_if_relative(url):
                #convert to absolute url
                #print("relative url", url)
                url = change_url_to_absolute(url, resp)
                #print("after convert", url)
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

def check_if_relative(url):
    #use regex to check if url is relative
    #returns true if url is relative
    #returns false if url is absolute or cases like #
    return bool(re.match(r'^[.]*[\/].+$', url))

def change_url_to_absolute(url, resp):
    return urljoin(resp.url, url)



