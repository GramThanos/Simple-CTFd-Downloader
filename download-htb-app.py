import os
import re
import sys
import yaml
import json
import time
import getopt
import hashlib
import logging
import requests
from tqdm import tqdm
from urllib.parse import urljoin, urlparse, quote

# Usage
USAGE_INFO = ('''
python download-htb.py
\tMain parameters:
\t\t-o\tThe output directory where the challenges will be saved
\tAuthentication parameters (only one of them is needed):
\t\t-t\tAn API token, get it from the console by running `localStorage.getItem("ctf-token")`

\tExample run:
\t\tpython3 download-htb-app.py -o ./ctf_name_files -t my_api_token
''')

# Set loggin options
logging.basicConfig(format='[%(levelname)s] %(message)s')
logging.getLogger().setLevel(logging.INFO)


VERIFY_SSL_CERT = False
if not VERIFY_SSL_CERT:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def slugify(text, fallback=None):
    if fallback == None:
        fallback = hashlib.md5(text.encode("utf-8")).hexdigest()
    text = re.sub(r"[\s]+", "-", text.lower())
    text = re.sub(r"[-]{2,}", "-", text)
    text = re.sub(r"[^a-zA-Z0-9\-\_\.]", "", text)
    text = re.sub(r"^-|-$", "", text)
    text = text.strip()
    if len(text) == 0:
        return fallback
    return text


def main(argv):

    try:
        opts, _ = getopt.getopt(argv, 'ho:t:', ['help', 'output=', 'token='])
    except getopt.GetoptError:
        print('python download-htb.py -h')
        sys.exit(2)

    if len(opts) < 2:
        print(USAGE_INFO)
        sys.exit()

    if '-h' in opts or '--help' in opts:
        print(USAGE_INFO)
        sys.exit()
    else:
        outputDir = ""
        headers = {
            #"Content-Type": "application/json"
            "accept" : "application/json, text/plain, */*",
            "accept-language" : "en-US,en;q=0.9,el;q=0.8,en-GB;q=0.7",
            "referer" : "https://app.hackthebox.com/",
            "user-agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
        }
        for opt, arg in opts:
            if opt in ('-o', '--output'):
                outputDir = arg  # Local directory to output docs
            if opt in ('-t', '--token'):
                headers["Authorization"] = f"Bearer {arg}"  # HTB API Token

        ctfName = 'Hack The Box - App'
        outputDir = outputDir.strip()

        # if no output dir, use ctf name
        if len(outputDir) < 1:
            outputDir = ctfName
        # if no ctf name, use output dir
        if len(ctfName) < 1:
            ctfName = outputDir

        # Create folder
        os.makedirs(outputDir, exist_ok=True)

        # Session to interact with the page
        S = requests.Session()

        # Download challenges info
        logging.info("Retrieving HTB App challenges...")
        challenges_info = []
        i = 1
        while True:
            logging.info(f"Retrieving HTB App challenges > Page {i}...")
            res = S.get(f"https://labs.hackthebox.com/api/v4/challenges?state=active&page={i}&sort_type=asc", headers=headers, verify=VERIFY_SSL_CERT).text
            info = json.loads(res)

            if (not 'data' in info) or (not 'links' in info) or (not 'meta' in info):
                print('Error reading api')
                sys.exit(2)

            challenges_info = challenges_info + info['data']

            if info['meta']['last_page'] == i:
                break

            i += 1
            logging.info("Wait for 1 sec so that we dont overload server ...")
            time.sleep(1)

        categories = {}
        logging.info("The app has %d challenges..." % len(challenges_info))
        desc_links = []

        for chall in challenges_info:
            logging.info("Wait for 5 sec so that we dont overload server ...")
            time.sleep(5)

            name = chall["name"]
            name_url_encoded = quote(name, safe="!~*'()")
            res = S.get(f"https://labs.hackthebox.com/api/v4/challenge/info/{name_url_encoded}", headers=headers, verify=VERIFY_SSL_CERT).text
            chall_info = json.loads(res)
            if not 'challenge' in chall_info:
                print(chall_info)
                print(f"https://labs.hackthebox.com/api/v4/challenge/info/{name_url_encoded}")
                logging.info("Failed to load challenge %s" % chall["category_name"])
                continue
            chall_info = chall_info['challenge']

            chall['category'] = chall["category_name"]
            chall_info['category'] = chall["category_name"]

            if chall['category'] not in categories:
                categories[chall['category']] = [chall]
            else:
                categories[chall['category']].append(chall)

            catDir = os.path.join(outputDir, slugify(chall['category']))
            challDir = os.path.join(catDir, slugify(chall["name"]))

            os.makedirs(challDir, exist_ok=True)
            os.makedirs(catDir, exist_ok=True)

            # Challenge info for yaml
            yaml_data = {
                'name': chall_info["name"],
                'author': chall_info["creator_name"],
                'homepage': f"https://app.hackthebox.com/",
                'category': chall_info['category_name'],
                'description': chall_info['description'],
                'value': chall_info['points'],
                'type': 'standard',
                'flags': [],
                'topics': [],
                'tags': [chall_info['difficulty']],
                'files': [],
                'state': 'visible',
                'version': '0.1'
            }


            with open(os.path.join(challDir, "README.md"), "w") as chall_readme:
                logging.info("Creating challenge readme: %s > %s" % (chall['category'], chall["name"]))
                chall_readme.write("# %s\n\n" % chall["name"])
                chall_readme.write("## Description\n\n%s\n\n" % chall_info["description"])

                # Download files of challenges
                if chall_info['download']:

                    chall_readme.write("## Files\n\n")

                    challFiles = os.path.join(challDir, "files")
                    os.makedirs(challFiles, exist_ok=True)

                    # Fetch file from remote server
                    F = S.get(f"https://labs.hackthebox.com/api/v4/challenge/download/{chall_info['id']}", headers=headers, stream=True, verify=VERIFY_SSL_CERT)

                    fname = slugify(chall_info['name'] + '.zip')
                    logging.info("Downloading file %s" % fname)
                    local_f_path = os.path.join(challFiles, fname)
                    yaml_data['files'].append(os.path.join('files', fname))

                    chall_readme.write("* [%s](files/%s)\n\n" % (fname, fname))

                    total_size_in_bytes = int(F.headers.get('content-length', 0))
                    progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=fname)

                    with open(local_f_path, "wb") as LF:
                        for chunk in F.iter_content(chunk_size=1024):
                            if chunk:
                                progress_bar.update(len(chunk))
                                LF.write(chunk)
                        LF.close()

                    progress_bar.close()

                # Save yaml
                with open(os.path.join(challDir, "challenge.yml"), 'w') as yaml_file:
                    yaml.dump(yaml_data, yaml_file, default_flow_style=False, sort_keys=False)
                
                chall_readme.close()

        with open(os.path.join(outputDir, "README.md"), "w") as ctf_readme:

            logging.info("Writing main CTF readme...")

            ctf_readme.write("# %s\n\n" % ctfName)
            ctf_readme.write("## About\n\n[insert description here]\n\n")
            ctf_readme.write("## Challenges\n\n")

            for category in categories:
                ctf_readme.write("### %s\n\n" % category)

                for chall in categories[category]:

                    chall_path = "challenges/%s/%s/" % (slugify(chall['category']), slugify(chall['name']))
                    ctf_readme.write("* [%s](%s)" % (chall['name'], chall_path))

                    if "tags" in chall and len(chall["tags"]) > 0:
                        ctf_readme.write(" <em>(%s)</em>" % ",".join(chall["tags"]))

                    ctf_readme.write("\n")

            ctf_readme.close()

        logging.info("All done!")


if __name__ == "__main__":
    main(sys.argv[1:])
