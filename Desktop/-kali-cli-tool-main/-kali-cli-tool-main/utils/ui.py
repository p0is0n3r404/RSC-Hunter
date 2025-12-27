class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

BANNER = rf"""{Colors.OKCYAN}
 /$$   /$$        /$$$$$$   /$$$$$$  /$$   /$$
| $$  /$$/       /$$__  $$ /$$__  $$| $$  /$$/
| $$ /$$/       | $$  \__/| $$  \ $$| $$ /$$/ 
| $$$$$/ /$$$$$$|  $$$$$$ | $$$$$$$$| $$$$$/  
| $$  $$|______/ \____  $$| $$__  $$| $$  $$  
| $$\  $$        /$$  \ $$| $$  | $$| $$\  $$ 
| $$ \  $$      |  $$$$$$/| $$  | $$| $$ \  $$
|__/  \__/       \______/ |__/  |__/|__/  \__/
                                                                                
    {Colors.OKGREEN}Kali Swiss Army Knife (K-SAK){Colors.ENDC}
    {Colors.BOLD}Created by p0is0n3r404{Colors.ENDC}
"""

def print_banner():
    print(BANNER)
