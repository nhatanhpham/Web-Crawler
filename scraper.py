import re
from urllib.parse import urlparse, urljoin, urldefrag
from utils import get_logger
import os.path
from bs4 import BeautifulSoup
from collections import defaultdict
import sys
import shelve
import os
import hashlib

class Our_Scraper:
    def __init__(self, config, restart):

        # Set of 32 bit fingerprint values
        self.fingerprint = set()
        self.domains = set()
        self.fingerprint_queries = set()

        # This either loads or deletes all of the previously stored data for the report
        if os.path.exists(config.data_file) and restart:
            os.remove(config.data_file)
        self.data = shelve.open(config.data_file)
        if restart:
            self.data["Tokens"] = defaultdict(int)
            self.data["Pages"] = 0
            self.data["Max"] = {"Words": 0, "Page_Name": ''}
            self.data["Subdomains"] = defaultdict(int)
            self.data.sync()     

        # Instead of using nltk stopwords, we used the exact stopwords given in the assignment
        self.stop_words = Our_Scraper.generate_stop_words()

        # This are the regular expressions to validate the subdomains of ics.uci.edu
        self.subdomain_good = re.compile(r".+//.+\.ics\.uci\.edu")
        self.subdomain_ignore = re.compile(r".+//www\.ics\.uci\.edu")


    def scraper(self, url, resp):

        # We found another unique page, even if we don't crawl it
        self.data["Pages"] += 1

        self.check_subdomain(resp.url)

        # We also do this checking in the extract_next_links function, I think one of them should not duplicate this
        if (resp and resp.status == 200 and resp.raw_response and resp.raw_response.content and sys.getsizeof(resp.raw_response.content) <= 500000):
            soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
            
            #Get textual information
            text = soup.get_text()
            hyperlinks = soup.findAll('a')

            #Crawl all pages with high textual information content > 400 characters excluding whitespace
            if self.high_textual_information(text, hyperlinks):
                word_count = self.tokenize_page(text)

                # If this page is similar in content, or the url is similar to another page, do not crawl it
                if self.split_url(url) and self.simhash():
                    return []

                self.update_max_page(word_count, resp.url)

                # Updates self.data shelve with all the new updates
                self.data.sync()

                links = extract_next_links(url, resp, hyperlinks)
                return links
        return []
    
    def split_url(self, url):
        domain_query = re.compile(r"(?P<domain>[^?]+)(?P<query>\?.*)*")
        matches = domain_query.match(url)
        if matches.group('domain') in self.domains:
            print("check domain", matches.group('domain'))
            if matches.group('query'):
                print("check query", matches.group('query'))
                return self.simhash_query(matches.group('query'))
        else:
            self.domains.add(matches.group('domain'))
            return False

    #returns true only if there's more than 400 characters excluding whitespace and text
    #that makes up hyperlinks
    def high_textual_information(self, text, hyperlinks):
        text_without_whitespace = sum(list(map(len, text.split())))
        hyperlink_char_count = 0
        for hyperlink in hyperlinks:
            if hyperlink is not None and hyperlink.text is not None:
                #this is an attempt to avoid pages that are pure link directories
                hyperlink_char_count += len(hyperlink.text.strip())
        return (text_without_whitespace - hyperlink_char_count) > 400

    def tokenize_page(self, text):
        word_count = 0

        # We need to extract the dictionary of tokens from self.data in order to add to it
        token_dict = self.data["Tokens"]
        
        # Keep track of the tokens on only the current page
        self.current_tokens = defaultdict(int)

        # Extract all the text from the page into an iterable
        for match in re.finditer(r"[a-zA-Z0-9']+", text):
            token = match.group()
            # make sure work is just not a symbol before counting it and adding to self.data
            if (not re.match(r"^(\W|_)+$", token)):
                # Keep track of how many words this page has, regardless of it is a stopword
                word_count += 1

                token = token.casefold()
                if token not in self.stop_words:
                    token_dict[token] += 1
                    self.current_tokens[token] += 1
        
         # Store the modified dictionary of tokens back into self.data
        self.data["Tokens"] = token_dict
       
        return word_count     

    def simhash_query(self, query):
        fingerprint_str = ""

        # Get binary representation of the query
        fingerprint_str = self.get_query_binary(query)
        print(fingerprint_str)

        if self.detect_similar(fingerprint_str):
            print("IS SIMILAR")
            return True

        self.fingerprint_queries.add(fingerprint_str)
        return False
    
    def get_query_binary(self, query):
        hash_function = hashlib.sha1(query.encode('utf-8'))
        #hash_function.update(token.encode('utf-8'))
            
        # This will get the int value of the url, within the valid representation of 32 bits
        hash_result = int(hash_function.hexdigest(), 16) % 4294967296

        # Returns the unique 32 bit binary representation of the word
        return str(bin(hash_result)[2:].zfill(32))

    def get_token_binary(self, token):
        hash_function = hashlib.sha1(token.encode('utf-8'))
        #hash_function.update(token.encode('utf-8'))
            
        # This will get the int value of the string, within the valid representation of 32 bits
        hash_result = int(hash_function.hexdigest(), 16) % 4294967296

        # Returns the unique 32 bit binary representation of the word
        return str(bin(hash_result)[2:].zfill(32))
    
    def simhash(self):
        words_in_binary = defaultdict(int)
        token_vector = []
        fingerprint_str = ""

        for token in self.current_tokens:
            # Dictionary of tokens containing 32 bit binary representations
            words_in_binary[token] = self.get_token_binary(token) 

        for i in range(32):
            sum_weights = 0
            for token, binary in words_in_binary.items():
                if binary[i] == '1':
                    sum_weights += self.current_tokens[token]
                    # print(f'for token {token}, i = {i} and binary = {binary} so adding {token_dict[token]} new_sum_weights = {sum_weights}')
                else:
                    sum_weights -= self.current_tokens[token]
                    # print(f'for token {token}, i = {i} and binary = {binary} so subtracting {token_dict[token]} to get new_sum_weights = {sum_weights}')
            # List vector formed by summing weights
            token_vector.append(sum_weights)

        # 16-bit fingerprint formed from vector list
        for i in token_vector:
            if i > 0:
                fingerprint_str += "1"
            else:
                fingerprint_str += "0"

        if self.detect_similar(fingerprint_str):
            return True

        self.fingerprint.add(fingerprint_str)
        return False
    
    def get_url_binary(self, url):
        hash_function = hashlib.sha1(url.encode('utf-8'))
        #hash_function.update(token.encode('utf-8'))
            
        # This will get the int value of the url, within the valid representation of 32 bits
        hash_result = int(hash_function.hexdigest(), 16) % 4294967296

        # Returns the unique 32 bit binary representation of the word
        return str(bin(hash_result)[2:].zfill(32))

    def get_token_binary(self, token):
        hash_function = hashlib.sha1(token.encode('utf-8'))
        #hash_function.update(token.encode('utf-8'))
            
        # This will get the int value of the string, within the valid representation of 32 bits
        hash_result = int(hash_function.hexdigest(), 16) % 4294967296

        # Returns the unique 32 bit binary representation of the word
        return str(bin(hash_result)[2:].zfill(32))

    def detect_similar(self, fingerprint):
        for fp in self.fingerprint:
            if (fingerprint == fp):
                # check if fingerprints are exact matches before computing similarity
                return True
            elif self.get_similarity(fingerprint, fp) > 0.9:
                # if not, check if they are similar
                return True
            
        return False

    def get_similarity(self, fp_1, fp_2):
        similar_bits = 0

        for i in range(32):
            if fp_1[i] == fp_2[i]:
                similar_bits += 1
    
        return similar_bits / 32.0
    

    def update_max_page(self, word_count, url):
        if word_count > self.data["Max"]["Words"]:
            max_page = self.data["Max"]
            max_page["Words"] = word_count
            max_page["Page_Name"] = url
            self.data["Max"] = max_page

    @staticmethod 
    def generate_stop_words():
        input_path = "Stop_Words.txt"
        input_file = open(input_path, 'r')

        stop_words = set()
        for word in input_file:
            stop_words.add(word[:-1])

        input_file.close()

        return stop_words

    # This checks if the given url is a subdomain of "ics.uci.edu", and if it is add 1 to the page
    # count for that subdomain
    def check_subdomain(self, url):
        match = self.subdomain_good.match(url)

        if match and not self.subdomain_ignore.match(url):
            subdomains = self.data["Subdomains"]
            subdomains[match.group(0).casefold().replace('www.','')] += 1
            self.data["Subdomains"] = subdomains

    # This gathers all of the data and prints out the report to the file named "Report.txt"
    def make_report(self):
        std_stdout = sys.stdout
        with open("Report.txt", 'w') as report:
            sys.stdout = report
            print(f"1. We found {self.data['Pages']} unique pages\n")
            print(f"2. The longest page in terms of the number of words is {self.data['Max']['Page_Name']}\n")

            print("3. The 50 most common words in the entire set of pages crawled under these domains are:")
            counter = 50
            for word, _ in sorted(self.data['Tokens'].items(), key = (lambda item : (-item[1], item[0]))):
                if counter <= 0:
                    break
                if len(word) > 1:
                    print(word)
                    counter -= 1
            
            print(f"\n4. We found {len(self.data['Subdomains'])} subdomains in the ics.uci.edu domain.\n")

            for subdomain, freq in sorted(self.data['Subdomains'].items(), key = (lambda item : (item[0], -item[1]))):
                print(f"{subdomain}, {freq}")

        sys.stdout = std_stdout


def extract_next_links(url, resp, links):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    hyperlinks = set()  
    for link in links:
        url = link.get('href')

        if url is not None:
            url = change_url_to_absolute(url, resp)

        if is_valid(url):
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
        #checks to see if valid domain
        if not re.match(r"(.+?\.)?(ics|cs|informatics|stat)\.uci\.edu", parsed.netloc):
            return False
        #avoids queries that involve actions
        if re.match(r"share|attachment|rev|action|do", parsed.query):
            return False
        #avoids calendar traps
        if re.match(r"(\d{4}-\d{2}-\d{2})|(\d{2}-\d{2}-\d{4})|(\d{2}-\d{2}-\d{2})|(\d{4}-\d{2})|(\d{2}-\d{4})", url):
            return False
        #avoids image files
        if re.match(r"img", url):
            return False
        #avoids directories that contain invalid files
        if re.match(r"^.*(calendar|uploads|files|attachment|wp-admin).*$", parsed.path.lower()):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz|apk|bib)$", parsed.path.lower())
    except TypeError:
        print ("TypeError for ", parsed)
        raise

def change_url_to_absolute(url, resp):
    absolute_url = urldefrag(urljoin(resp.raw_response.url, url)).url
    return absolute_url


