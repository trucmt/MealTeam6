from flask import Flask, request, render_template_string, redirect, url_for
import argparse
import urllib
from urllib.request import Request, urlopen
from urllib.parse import urlparse
import os
import re
import requests

app = Flask(__name__)

HTML = """
<!doctype html>
<html>
<head>
    <title>Clickjacking Test Tool</title>
    <link rel="stylesheet" type="text/css" href="/static/style.css">
</head>
<body>
    <h2>Upload File with URLs to Check for Clickjacking</h2>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            content = file.read().decode('utf-8')
            results = check_clickjacking(content)
            return render_template_string(results)
    return HTML

def check_clickjacking(content):
    hdr = {'User-Agent': 'Mozilla/5.0'}
    results = ""
    for target in content.splitlines():
        t = target.strip()
        if not t.startswith(('http://', 'https://')):
            t = 'https://' + t
        try:
            req = Request(t, headers=hdr)
            data = urlopen(req, timeout=10)
            headers = data.info()
            response= requests.get(t)
            vuln= False

            frame_buster = re.search(r'<script>(.*)if\(top \!= self\)\s*{', response.text, re.DOTALL | re.IGNORECASE)
            pattern_onbeforeunload = r'<script>\s*window\.onbeforeunload[^<]*</script>.*?<iframe src="([^"]+)"'
            match_pattern_onbeforeunload = re.search(pattern_onbeforeunload, response.text, re.IGNORECASE | re.DOTALL)
            pattern_location= r'<script>\s*var\s+location\s*=\s*[^;]+;\s*</script>.*?<iframe src="([^"]+)"'
            match_pattern_location= re.search(pattern_location, response.text, re.IGNORECASE | re.DOTALL)
            pattern_location_1=r'<script>\s*window\.defineSetter\("location",\s*function\(\)\s*{}\);\s*</script>.*?<iframe src="([^"]+)">'
            match_pattern_location_1= re.search(pattern_location, response.text, re.IGNORECASE | re.DOTALL)
            x_frame_options = response.headers.get('X-Frame-Options', '')
            content_security_policy = response.headers.get('Content-Security-Policy', '')
            
            desired_domain= t

            if "Referer" in req.headers:
                host_url = req.host_url
                referer_url = req.headers["Referer"]
                if not referer_url.startswith(host_url):
                   vuln = True
            if not (("X-Frame-Options") or ("x-frame-options") or ("Content-Security-Policy") or ("content-security-policy")  or ("frame-ancestors")) in headers:
                vuln = True

            if match_pattern_onbeforeunload:
               iframe_src = match_pattern_onbeforeunload.group(1)  # Lấy giá trị của src
               if iframe_src.startswith(desired_domain):
                print("The iframe src matches the desired domain and is linked to the onbeforeunload script.")
               else:
                print("The iframe src does not match the desired domain but is linked to the onbeforeunload script.")
                vuln= True
            
            if match_pattern_location:
               iframe_src = match_pattern_location.group(1)  # Lấy giá trị của src
               if iframe_src.startswith(desired_domain):
                print("The iframe src matches the desired domain and is linked to the location script.")
               else:
                print("The iframe src does not match the desired domain but is linked to the location script.")
                vuln= True

            if match_pattern_location_1:
               iframe_src = match_pattern_location_1.group(1)  # Lấy giá trị của src
               if iframe_src.startswith(desired_domain):
                print("The iframe src matches the desired domain and is linked to the location 1 script.")
               else:
                print("The iframe src does not match the desired domain but is linked to the location 1 script.")
                vuln= True    
 
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

            if 'X-Frame-Options' not in headers:
                results += f"<p style='color: green;'>Target: {t} is Vulnerable</p>"
            elif frame_buster:
                print((f"Target: {t} is Vulnerable", "red"))           
            elif vuln ==True:
                print((f"Target: {t} is Vulnerable", "red"))
            else:
                results += f"<p style='color: green;'>Target: {t} is not Vulnerable</p>"
        except Exception as e:
            results += f"<p>Error checking {t}: {str(e)}</p>"
    return results

if __name__ == '__main__':
    app.run(debug=True)
