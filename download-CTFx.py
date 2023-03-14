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
USAGE_INFO = ('''python download.py
\tMain parameters:
\t\t-u\tThe URL of the CTFx instance
\t\t-n\tThe name of the event
\t\t-o\tThe output directory where the challenges will be saved
\tAuthentication parameters (only one of them is needed):
\t\t-c\tAn active PHP session cookie for a connected account (value only), e.g. aabbccdd

\tExample run:
\t\tpython3 download-CTFx.py -u http://ctf.url -n ctf_name -o ./ctf_name_files -c php_session_value
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
        opts, _ = getopt.getopt(argv, 'hu:n:o:c:', ['help', 'url=', 'name=', 'output=', 'cookie='])
    except getopt.GetoptError:
        print('python download.py -h')
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
                baseUrl = arg  # URL of the CTFd
            if opt in ('-n', '--name'):
                ctfName = arg  # CTFd Name
            if opt in ('-o', '--output'):
                outputDir = arg  # Local directory to output docs
            if opt in ('-c', '--cookie'):
                headers["Cookie"] = f"PHPSESSID={arg}"  # CTFd API Token

        ctfName = ctfName.strip()
        outputDir = outputDir.strip()

        # if no output dir, use ctf name
        if len(outputDir) < 1:
            outputDir = slugify(ctfName)
        # if no ctf name, use output dir
        if len(ctfName) < 1:
            ctfName = slugify(outputDir)

        # Create folder
        os.makedirs(outputDir, exist_ok=True)

        # Session to interact with the page
        S = requests.Session()

        # Download front page
        index_html = S.get(f"{baseUrl}", headers=headers, verify=VERIFY_SSL_CERT).text
        with open(os.path.join(outputDir, "index.html"), "w") as index_html_file:
            logging.info("Saving CTF's index page ...")
            index_html_file.write(index_html)

        # Load categories names
        logging.info(f"Loading categories ...")
        page = S.get(f"{baseUrl}/challenges", headers=headers, verify=VERIFY_SSL_CERT).text
        #m = re.findall(r'<a class="category-link" href="/challenges\?category=([^"&]+)">([^<]+)</a>', page) # CTF_A
        m = re.findall(r'<a class="btn-solid btn-solid-warning" href="challenges-category-([^"&]+)"[^>]*>([^<]+)</a>', page) # CTF_B
        categories = []
        for category in m:
            if not category[0] in categories:
                #categories.append(category[0]) # CTF_A
                categories.append(category[1].strip().rstrip('.html')) # CTF_B

        if len(categories) == 0:
            logging.info("Error! No categories were found.")
            sys.exit()

        logging.info(f"Found {len(categories)} categories")

        # Load challenges for each category
        for category in categories:
            logging.info(f'Loading category "{category}" ...')
            #page = S.get(f"{baseUrl}/challenges?category={category}", headers=headers, verify=VERIFY_SSL_CERT).text # CTF_A
            page = S.get(f"{baseUrl}/challenges-category-{category.replace(' ', '+')}", headers=headers, verify=VERIFY_SSL_CERT).text # CTF_B

            # Split html and keep only challenges
            #challenges_code = page.split('<div class="panel panel-default challenge-container">')[1:] # CTF_A
            challenges_code = page.split('<div class="card-header">')[1:] # CTF_B
            challenges_code[-1] = challenges_code[-1].split('<div id="footer">')[0] # CTF_A + CTF_B

            logging.info(f'Found {len(challenges_code)} challenges in category {category}')

            for code in challenges_code:
                #name = re.findall(r'<a href="challenge\?id=(\d+)">([^<]+)</a>', code)[0][1] # CTF_A
                name = re.findall(r'<a href="challenge-id-(\d+)\.html">([^<]+)</a>', code)[0][1].strip() # CTF_B
                #value = re.findall(r'<small>(\d+) Points</small>', code)[0][0] # CTF_A
                value = re.findall(r'(\d+) Points', code)[0][0] # CTF_B
                #description = code.split('<div class="challenge-description">')[-1].split('<div class="challenge-files">')[0] # CTF_A
                description = code.split('<div class="card-content">')[-1].split('<div style="margin-top:8px; display:flex; flex-wrap: wrap">')[0] # CTF_B
                description = description.replace('<br />', '\n')
                description = re.sub("<[^>]+>", "", description)
                description = re.sub(" +", " ", description)
                description = description.strip()
                #files_code = code.split('<div class="challenge-files">')[-1].split('<div class="challenge-submit">')[0] # CTF_A
                files_code = code.split('<div style="margin-top:8px; display:flex; flex-wrap: wrap">')[-1].split('<div class="tag tag-inline" style="margin-bottom:0px">')[0] # CTF_B
                #files_info = re.findall(r'href="(download\?[^"]+)">([^<]+)</a>', files_code)  # CTF_A

                files_info = re.findall(r'<a href="([^"]+)"[^>]*>\s*<div[^>]*>\s*<img[^>]*/>\s*([^<]+)<', files_code)  # CTF_B
                files = []
                for file in files_info:
                    #files.append(os.path.join('files', slugify(file[1]))) # CTF_A
                    if file[0].startswith("http"):
                        files.append(file[0].strip())
                    else:
                        files.append(os.path.join('files', file[1].strip()))
                #print(name)
                #print(files)

                # make dirs
                catDir = os.path.join(outputDir, slugify(category))
                challDir = os.path.join(catDir, slugify(name))

                # If folder exists, skip
                if os.path.exists(challDir):
                    logging.info(f'Challenge {name} already downloaded... skipping...')
                    continue
                logging.info(f'Loading {name} challenge in category {category}')

                # make dirs
                os.makedirs(challDir, exist_ok=True)
                os.makedirs(catDir, exist_ok=True)
                if len(files) > 0:
                    challFiles = os.path.join(challDir, "dist")
                    os.makedirs(challFiles, exist_ok=True)

                # Download files
                for file in files_info:

                    if file[0].startswith("http"):
                        f_name = urlparse(file[0]).path.split("/")[-1]
                        f_url = file[0]
                    else:
                        f_name = slugify(file[1])
                        f_url = urljoin(baseUrl, file[0])
                    local_f_path = os.path.join(challFiles, f_name)
                    # Fetch file from remote server
                    F = S.get(f_url, stream=True, verify=VERIFY_SSL_CERT)

                    logging.info("Downloading file %s" % f_name)
                    total_size_in_bytes = int(F.headers.get('content-length', 0))
                    progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=f_name)
                    with open(local_f_path, "wb") as LF:
                        for chunk in F.iter_content(chunk_size=1024):
                            if chunk:
                                progress_bar.update(len(chunk))
                                LF.write(chunk)
                        LF.close()
                    progress_bar.close()

                    #chall_readme.write("* [%s](files/%s)\n\n" % (f_name, f_name))

                yaml_data = {
                    'name': name,
                    'author': baseUrl,
                    'homepage': baseUrl,
                    'category': category,
                    'description': description,
                    'value': value,
                    'type': '-',
                    'flags': [],
                    'topics': [],
                    'tags': [],
                    'files': files,
                    'hints': [],
                    'state': 'visible',
                    'version': '0.1'
                }

                with open(os.path.join(challDir, "README.md"), "w") as chall_readme:
                    logging.info("Creating challenge readme: %s > %s" % (category, name))
                    chall_readme.write("# %s\n\n" % name)
                    chall_readme.write("## Description\n\n%s\n\n" % description)

                    if len(files) > 0:
                        chall_readme.write("## Files\n\n")

                        for file in files_info:
                            f_name = slugify(file[1])
                            chall_readme.write("* [%s](files/%s)\n\n" % (f_name, f_name))

                # Save yaml
                with open(os.path.join(challDir, "challenge.yml"), 'w') as yaml_file:
                    yaml.dump(yaml_data, yaml_file, default_flow_style=False, sort_keys=False)
                

        with open(os.path.join(outputDir, "README.md"), "w") as ctf_readme:

            logging.info("Writing main CTF readme...")

            ctf_readme.write("# %s\n\n" % ctfName)
            ctf_readme.write("## About\n\n[insert description here]\n\n")
            ctf_readme.write("## Challenges\n\n")

            #for category in categories:
            #    ctf_readme.write("### %s\n\n" % category)
            #
            #    for chall in categories[category]:
            #
            #        chall_path = "challenges/%s/%s/" % (slugify(chall['category']), slugify(chall['name']))
            #        ctf_readme.write("* [%s](%s)" % (chall['name'], chall_path))
            #
            #        if "tags" in chall and len(chall["tags"]) > 0:
            #            ctf_readme.write(" <em>(%s)</em>" % ",".join(chall["tags"]))
            #
            #        ctf_readme.write("\n")

            ctf_readme.close()

        logging.info("All done!")

        #if len(desc_links) > 0:
        #    logging.warning("Warning, some links were found in challenge descriptions, you may need to download these files manually.")
        #    for ccategory, cname, link in desc_links:
        #        logging.warning("    %s > %s : %s" % (ccategory, cname, link))


if __name__ == "__main__":
    main(sys.argv[1:])
