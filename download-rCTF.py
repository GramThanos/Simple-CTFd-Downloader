import os
import re
import sys
import yaml
import json
import getopt
import hashlib
import logging
import requests
from tqdm import tqdm
from urllib.parse import urljoin, urlparse

# Usage
USAGE_INFO = ('''
python download.py
\tMain parameters:
\t\t-u\tThe URL of the rCTF instance
\t\t-n\tThe name of the event
\t\t-o\tThe output directory where the challenges will be saved
\tAuthentication parameters (only one of them is needed):
\t\t-t\tAn API token generated through an account's settings
\t\t-c\tAn active session cookie for a connected account (value only), e.g. aabbccdd.abcd

\tExample run:
\t\tpython3 download.py -u http://ctf.url -n ctf_name -o ./ctf_name_files -t my_api_token
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
        opts, _ = getopt.getopt(argv, 'hu:n:o:t:c:', ['help', 'url=', 'name=', 'output=', 'token=', 'cookie='])
    except getopt.GetoptError:
        print('python download-rCTF.py -h')
        sys.exit(2)

    if len(opts) < 4:
        print(USAGE_INFO)
        sys.exit()

    if '-h' in opts or '--help' in opts:
        print(USAGE_INFO)
        sys.exit()
    else:
        baseUrl, ctfName, outputDir, = "", "", ""  # defaults?
        headers = {"Content-Type": "application/json"}
        for opt, arg in opts:
            if opt in ('-u', '--url'):
                baseUrl = arg  # URL of the CTFd
            if opt in ('-n', '--name'):
                ctfName = arg  # CTFd Name
            if opt in ('-o', '--output'):
                outputDir = arg  # Local directory to output docs
            if opt in ('-t', '--token'):
                headers["Authorization"] = f"Token {arg}"  # CTFd API Token
            elif opt in ('-c', '--cookie'):
                headers["Cookie"] = f"session={arg}"  # CTFd API Token

        os.makedirs(outputDir, exist_ok=True)

        apiUrl = urljoin(baseUrl, '/json')

        logging.info("Connecting to API: %s" % apiUrl)

        S = requests.Session()
        X = S.get(f"{apiUrl}/challs.json", headers=headers, verify=VERIFY_SSL_CERT).text
        challs = json.loads(X)

        categories = {}

        logging.info("Retrieved %d challenges..." % len(challs['data']))

        desc_links = []

        for chall in challs['data']:

            Y = chall

            if Y["category"] not in categories:
                categories[Y["category"]] = [Y]
            else:
                categories[Y["category"]].append(Y)

            catDir = os.path.join(outputDir, slugify(Y["category"]))
            challDir = os.path.join(catDir, slugify(Y["name"]))

            os.makedirs(challDir, exist_ok=True)
            os.makedirs(catDir, exist_ok=True)

            # Challenge info for yaml
            yaml_data = {
                'name': Y["name"],
                'author': Y["author"],
                'homepage': baseUrl,
                'category': Y["category"],
                'description': Y['description'],
                'value': Y['points'],
                'type': 'standard',
                'flags': [],
                'topics': [],
                'tags': [],
                'files': [],
                'hints': [],
                'state': 'visible',
                'version': '0.1'
            }


            with open(os.path.join(challDir, "README.md"), "w") as chall_readme:
                logging.info("Creating challenge readme: %s > %s" % (Y["category"], Y["name"]))
                chall_readme.write("# %s\n\n" % Y["name"])
                chall_readme.write("# by %s\n\n" % Y["author"])
                chall_readme.write("## Description\n\n%s\n\n" % Y["description"])

                files_header = False

                # Find links in description
                links = re.findall(r'https?://[^\s\)]+', Y["description"])
                # Find MD images in description
                md_links = re.findall(r'!\[(.*)\]\(([^\s\)]+)\)', Y["description"])

                for link_desc, link in md_links:
                    if link in links:
                        links.remove(link)

                # Note links from descriptions
                if len(links) > 0:
                    for link in links:
                        desc_links.append((Y["category"], Y["name"], link))

                # Download images from descriptions
                if len(md_links) > 0:
                    challFiles = os.path.join(challDir, "images")
                    os.makedirs(challFiles, exist_ok=True)

                    for link_desc, link in md_links:
                        dl_url = urljoin(baseUrl, link)

                        F = S.get(dl_url, stream=True, verify=VERIFY_SSL_CERT)
                        fname = slugify(urlparse(dl_url).path.split("/")[-1])
                        logging.info("Downloading image %s" % fname)

                        if link[0] in ["/", "\\"]:
                            link = link[1:]

                        local_f_path = os.path.join(challFiles, fname)

                        total_size_in_bytes = int(F.headers.get('content-length', 0))
                        progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=fname)

                        with open(local_f_path, "wb") as LF:
                            for chunk in F.iter_content(chunk_size=1024):
                                if chunk:
                                    progress_bar.update(len(chunk))
                                    LF.write(chunk)
                            LF.close()

                        progress_bar.close()

                # Download files of challenges
                if "files" in Y and len(Y["files"]) > 0:

                    if not files_header:
                        chall_readme.write("## Files\n\n")

                    challFiles = os.path.join(challDir, "files")
                    os.makedirs(challFiles, exist_ok=True)

                    for file in Y["files"]:

                        # Fetch file from remote server
                        f_url = file['url'] #urljoin(baseUrl, file)
                        F = S.get(f_url, stream=True, verify=VERIFY_SSL_CERT)

                        fname = slugify(file['name']) #urlparse(f_url).path.split("/")[-1]
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

        if len(desc_links) > 0:
            logging.warning("Warning, some links were found in challenge descriptions, you may need to download these files manually.")
            for ccategory, cname, link in desc_links:
                logging.warning("    %s > %s : %s" % (ccategory, cname, link))


if __name__ == "__main__":
    main(sys.argv[1:])
