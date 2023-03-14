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
python download-ctfcafe.py
\tMain parameters:
\t\t-u\tThe URL of the CTF_Cafe instance
\t\t-n\tThe name of the event
\t\t-o\tThe output directory where the challenges will be saved
\tAuthentication parameters (only one of them is needed):
\t\t-c\tAn active session cookie for a connected account (value only), e.g. aabbccdd.abcd

\tExample run:
\t\tpython3 download-ctfcafe.py -u https://ctf.link.com/ -n ctf_name -o ./ctf_name_files -c session.data
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
        opts, _ = getopt.getopt(argv, 'hu:n:o:t:c:', ['help', 'url=', 'name=', 'output=', 'cookie='])
    except getopt.GetoptError:
        print('python download-ctfcafe.py -h')
        sys.exit(2)

    if len(opts) < 3:
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
                baseUrl = arg  # URL of the CTF
            if opt in ('-n', '--name'):
                ctfName = arg  # CTF Name
            if opt in ('-o', '--output'):
                outputDir = arg  # Local directory to output docs
            elif opt in ('-c', '--cookie'):
                headers["Cookie"] = f"connect.sid={arg}"  # Session Cookie

        ctfName = ctfName.strip()
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

        # Download front page
        index_html = S.get(f"{baseUrl}", headers=headers, verify=VERIFY_SSL_CERT).text
        with open(os.path.join(outputDir, "index.html"), "w") as index_html_file:
            logging.info("Saving CTF's index page ...")
            index_html_file.write(index_html)


        apiUrl = urljoin(baseUrl, '/api')

        # Download challenges
        logging.info("Connecting to API: %s" % apiUrl)
        res = S.get(f"{apiUrl}/user/getChallenges", headers=headers, verify=VERIFY_SSL_CERT).text
        info = json.loads(res)

        categories = {}
        logging.info("The event has %d challenges..." % len(info['challenges']))


        for chall in info['challenges']:
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
                'name': chall["name"],
                'author': '-',
                'homepage': f"{baseUrl}",
                'category': chall['category'],
                'description': chall['info'],
                'value': chall['points'],
                'type': 'standard',
                'flags': [],
                'topics': [],
                'tags': [],
                'files': [],
                'hints': [],
                'state': 'visible',
                'version': '0.1'
            }

            # Add hints
            for hint in chall['hints']:
                yaml_data['hints'].append({
                    'content': hint['content'],
                    'cost': hint['cost']
                })


            with open(os.path.join(challDir, "README.md"), "w") as chall_readme:
                logging.info("Creating challenge readme: %s > %s" % (chall['category'], chall["name"]))
                chall_readme.write("# %s\n\n" % chall["name"])
                chall_readme.write("## Description\n\n%s\n\n" % chall["info"])

                # Download files of challenges
                if chall['file']:

                    chall_readme.write("## Files\n\n")

                    challFiles = os.path.join(challDir, "files")
                    os.makedirs(challFiles, exist_ok=True)

                    # Fetch file from remote server
                    F = S.get(f"{apiUrl}/assets/{chall['file']}", stream=True, verify=VERIFY_SSL_CERT)

                    fname = slugify(chall['file'])
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
