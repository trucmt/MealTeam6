#!/usr/bin/python3
from urllib.request import Request, urlopen
import argparse
from sys import exit
import urllib
import requests
import urllib.request
from termcolor import colored
from urllib.parse import urlparse
import re

vuln=False
parser = argparse.ArgumentParser(
    description='Scan the website for clickjacking')
parser.add_argument(
    "-f", type=str, help="File to store a list of urls", required=True)


content = parser.parse_args()

d = open(content.f, 'r')
hdr = {'User-Agent': 'Mozilla/5.0'}

try:
    for target in d.readlines():
        t = target.strip('\n')
        if (("http") or ("https")) not in t:
            t = "https://"+t  
        try:
            req = Request(t, headers=hdr)
            data = urlopen(req, timeout=10)
            response= requests.get(t)
            filename = urlparse(t).netloc
            headers = data.info()
            if "Referer" in req.headers:
                host_url = req.host_url
                referer_url = req.headers["Referer"]
                if not referer_url.startswith(host_url):
                   vuln = True
            if not (("X-Frame-Options") or ("x-frame-options") or ("Content-Security-Policy") or ("content-security-policy")  or ("frame-ancestors")) in headers:
                vuln = True
            
            frame_buster = re.search(r'<script>(.*)if\(top \!= self\)\s*{', response.text, re.DOTALL | re.IGNORECASE)
            x_frame_options = response.headers.get('X-Frame-Options', '')
            content_security_policy = response.headers.get('Content-Security-Policy', '')

            if content_security_policy:
               csp_policies = content_security_policy.split(';')
               frame_ancestors_content = frame_ancestors.group(1)
               frame_ancestors = re.search(r'frame-ancestors\s(.*?);', content_security_policy)
               if 'frame-ancestors' in content_security_policy:
                if frame_ancestors_content.lower() == '\'self *\'':
                    print(('red_msg', f'[!] The site may be vulnerable to clickjacking. Frame-ancestors content: {frame_ancestors_content}'))
                    vuln= True

            if x_frame_options:
                if x_frame_options.lower() == 'allow-from *':
                   print(('red_msg', f'[!] The site may be vulnerable to clickjacking. X-Frame-Options content: {x_frame_options}'))
                   vuln= True

            if frame_buster:
                print(('orange_msg', f'[!] Frame-buster found on the page, but can be bypassed using the \'sandbox=\"allow-forms\"\' attribute.'))
                print(colored(f"Target: {t} is Vulnerable", "green"))
                print(colored(f"Generating {filename}.html demo File", "yellow"))
                demo = """
                    <html>
                    <head><title>Clickjack demo page with frame-buster</title></head>
                    <body>
                    <p>Website is vulnerable to clickjacking! with frame-buster</p>
                    <iframe sandbox="allow-forms" src="{}" width="500" height="500"></iframe>
                    </body>
                    </html>
                    """.format(t)
                if ":" in filename:
                    url = filename.split(':')
                    filename=url[0]              
                with open(filename+".html", "w") as pf:
                    pf.write(demo)
                print(colored(f"Clickjacking file Created SuccessFully, Open {filename}.html to get the demo", "blue"))
            
            elif vuln ==True:
                print(colored(f"Target: {t} is Vulnerable", "green"))
                print(colored(f"Generating {filename}.html demo File", "yellow"))
                demo = """
                    <html>
                    <head><title>Clickjack page</title></head>
                    <body>
                    <p>Website is vulnerable to clickjacking!</p>
                    <iframe src="{}" width="500" height="500"></iframe>
                    </body>
                    </html>
                    """.format(t)
                if ":" in filename:
                    url = filename.split(':')
                    filename=url[0]              
                with open(filename+".html", "w") as pf:
                    pf.write(demo)
                print(colored(f"Clickjacking demo file Created SuccessFully, Open {filename}.html to get the demo", "blue"))
            else:
                vuln == False
                print(colored(f"Target: {t} is not Vulnerable", "red"))
                print("Testing Other Url's in the List")
        except KeyboardInterrupt as k:
            print("No Worries , I'm here to handle your KeyBoard Interrupts \n")
        except urllib.error.URLError as e:
            # handling HTTP 403 Forbidden timeout...
            print(f"Target {t} has some HTTP Errors via http:// lets let https:// ", exception)
        except requests.HTTPError as exception:
            print(f"Target {t} has some HTTP Errors :--> ", exception)
        except Exception as e:
            print("Exception Occured with Description ----> ", e)
            raise("Target Didn't Responsed")
    print("All Targets Tested Successfully !!")
except:
    print("[*] Usage: python3 clickjackingByMealTeam6.py -f <file_name>")
    print("[*] The Code might not worked for you , please retry & try --help option to know more")
    exit(0)
