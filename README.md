ClickJackingByMealTeam6

This utility streamlines the process of detecting Clickjacking Vulnerabilities by allowing you to input a file with a list of potential targets. Should a target be susceptible, the tool will automatically create a Proof of Concept (PoC) exploit for each affected target.

**What is Clickjacking?**
Clickjacking, also known as a User Interface redress attack, is a deceptive practice where a user is misled into clicking on an element that is different from what they believe they are interacting with. This can lead to the disclosure of sensitive information or unauthorized control over their computer, all while engaging with what appears to be harmless web content.

The absence of an X-Frame-Options header in the server's response suggests that this website may be vulnerable to a clickjacking attack. The X-Frame-Options HTTP response header is designed to determine whether a browser is permitted to render a page within a frame or an iframe.

Websites can implement the "X-Frame-Options" header in their responses to protect against clickjacking attacks, ensuring their content is not embedded into other sites.
Reference
Installation:
git clone https://github.com/trucmt/MealTeam6.git
cd MealTeam6
pip install -r req.txt
Example:
Example Usage of the Tool
p/s:
put the domain in the file named: domains.txt so you can:

python3 clickjackingByMealTeam6.py -f domains.txt
the domains.txt contains:
1:the_target_1
2:the_target_2
3:the_target_3

Allowed Targets Format:
http://thetarget.com
thetarget.com
www.thetarget.com
https://thetarget.com/
https://IP:port
IP:port
http://IP:port/login
http://www.thetarget.com/directory
https://www.thetarget.com/directory
Benefits:
The program will process all the specified targets from the provided file. For each target that is found to be vulnerable, it will generate an exploit Proof of Concept by creating an HTML file named after the target (TheTargetName.html). If a target is determined to be secure and not susceptible to clickjacking, the program will output a message indicating that the target is not vulnerable.
