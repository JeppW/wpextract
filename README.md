# wpextract
A proof-of-concept tool for extracting user email addresses from WordPress sites. 

The script abuses the `search` parameter on the `/wp-json/wp/v2/users` WordPress REST API endpoint to extract email addresses on a character-by-character basis.

Note: This issue is public. Public ticket available at https://core.trac.wordpress.org/ticket/53784.

## Usage
Run the Python script and specify the URL of the target WordPress site.

Example: `python3 wpextract.py --url https://some.website.com/news`

Optional parameters:

```
$ python3 wpextract.py -h
usage: wpextract.py [-h] -u URL [-t THREADS] [-m MAX_RETRIES] [-a ALPHABET] [-o FILENAME] [-s]

WordPress email extractor - Proof of Concept tool

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL of target WordPress instance
  -t THREADS, --threads THREADS
                        number of threads to use
  -m MAX_RETRIES, --max-retries MAX_RETRIES
                        maximum number of retries on network errors
  -a ALPHABET, --alphabet ALPHABET
                        alphabet used in email extraction
  -o FILENAME, --out FILENAME
                        save result to a local file
  -s, --silent          don't log non-essential messages
```