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
python download-kosenctfx.py
\tMain parameters:
\t\t-u\tThe URL of the kosenctfx instance
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


def slugify(text, fallback=None, isdir=False):
    if fallback == None:
        fallback = hashlib.md5(text.encode("utf-8")).hexdigest()
    
    text = re.sub(r"[\s]+", "-", text.lower())
    text = re.sub(r"[-]{2,}", "-", text)
    text = re.sub(r"[^a-zA-Z0-9\-\_\.]", "", text)
    #if isdir:
    #    text = re.sub(r"\.", "", text)
    text = re.sub(r"^-|-$", "", text)
    text = re.sub(r"\.\.+", ".", text) # dont allow multiple dots
    text = re.sub(r"\.+$", "", text) # dont allow dots at the end

    text = text.strip()
    # If name is empty
    if len(text) == 0:
        return fallback
    # If name is too big
    if len(text) > 256:
        return text[:255]
    return text


def main(argv):

    try:
        opts, _ = getopt.getopt(argv, 'hu:n:o:t:c:', ['help', 'url=', 'name=', 'output=', 'token=', 'cookie='])
    except getopt.GetoptError:
        print('python download.py -h')
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


        tasksUrl = urljoin(baseUrl, 'tasks')

        logging.info("Connecting to tasks: %s" % tasksUrl)

        X = S.get(f"{tasksUrl}/", headers=headers, verify=VERIFY_SSL_CERT).text
        try:
            X = X.split('<script id="__NEXT_DATA__" type="application/json">')[1].split('</script>')[0]
            #print(json.loads(X))
            challs = json.loads(X)['props']['pageProps']['tasks']
        except Exception as e:
            print(e)
            logging.info("Failed to load challenges...")
            try:
                with open(os.path.join(outputDir, "data.json"), "r") as f:
                    X = f.read()
                    challs = json.loads(X)['o']
            except Exception as e:
                print(e)
                logging.info("Failed to load challenges...")
                return

        categories = {}

        logging.info("Retrieved %d challenges..." % len(challs))

        desc_links = []
        failed_to_download_links = []

        for chall in challs:

            if not "category" in chall or not chall["category"] or len(chall["category"]) < 1:
                if "tags" in chall and len(chall["tags"]) > 0:
                    chall["category"] = chall["tags"][0]
                else:
                    chall["category"] = 'none'

            if chall["category"] not in categories:
                categories[chall["category"]] = [chall]
            else:
                categories[chall["category"]].append(chall)

            catDir = os.path.join(outputDir, slugify(chall["category"], isdir=True))
            challDir = os.path.join(catDir, slugify(chall["name"], isdir=True))

            os.makedirs(challDir, exist_ok=True)
            os.makedirs(catDir, exist_ok=True)

            # Challenge info for yaml
            yaml_data = {
                'name': chall["name"],
                'author': chall["author"],
                'homepage': baseUrl,
                'category': chall["category"],
                'description': chall['description'],
                'value': chall['score'],
                'type': 'standard',
                'flags': [],
                'topics': [],
                'tags': chall['tags'],
                'files': [],
                'hints': [],
                'state': 'visible',
                'version': '0.1'
            }


            with open(os.path.join(challDir, "README.md"), "w") as chall_readme:
                logging.info("Creating challenge readme: %s > %s" % (chall["category"], chall["name"]))
                chall_readme.write("# %s\n\n" % chall["name"])
                chall_readme.write("## Description\n\n%s\n\n" % chall["description"])

                files_header = False

                # Find links in description
                links = []
                if not chall["description"]:
                    chall["description"] = ''
                detect_links = re.findall(r'https?://[^\s\)\"\']+', chall["description"])
                for link in detect_links:
                    if ('](https://' in link) or ('](http://' in link):
                        links.append(link.split('](')[1].rstrip(')'))
                    else:
                        links.append(link)

                # Find MD images in description
                md_image_links = re.findall(r'!\[(.*)\]\(([^\s\)]+)\)', chall["description"])
                #md_links = re.findall(r'(?<!!)\[(.*)\]\(([^\s\)]+)\)', chall["description"])

                img_links = []
                # Find images in links
                for link in links:
                    if link.lower().endswith('.png') or link.lower().endswith('.jpg') or link.lower().endswith('.jpeg') or link.lower().endswith('.gif') or link.lower().endswith('.tiff'):
                        img_links.append(link)
                        links.remove(link)

                # Remove links already in the md format
                for link_desc, link in md_image_links:
                    if link in links:
                        links.remove(link)
                    if link in img_links:
                        img_links.remove(link)


                # Note links from descriptions
                if len(links) > 0:
                    for link in links:
                        desc_links.append((chall["category"], chall["name"], link))

                # Download images from descriptions
                if len(md_image_links) > 0:
                    challFiles = os.path.join(challDir, "images")
                    os.makedirs(challFiles, exist_ok=True)

                    for link_desc, link in md_image_links:
                        dl_url = urljoin(baseUrl, link)

                        try:
                            F = S.get(dl_url, stream=True, verify=VERIFY_SSL_CERT)
                        except Exception as e:
                            failed_to_download_links.append((chall["category"], chall["name"], dl_url))
                            continue
                        fname = slugify(urlparse(dl_url).path.split("/")[-1])
                        logging.info("Downloading image %s" % fname)

                        #if link[0] in ["/", "\\"]:
                        #    link = link[1:]

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

                # Links that are images
                if len(img_links) > 0:
                    challFiles = os.path.join(challDir, "images")
                    os.makedirs(challFiles, exist_ok=True)

                    for link in img_links:
                        dl_url = link

                        try:
                            F = S.get(dl_url, stream=True, verify=VERIFY_SSL_CERT)
                        except Exception as e:
                            failed_to_download_links.append((chall["category"], chall["name"], dl_url))
                            continue
                        fname = slugify(urlparse(dl_url).path.split("/")[-1])
                        logging.info("Downloading image %s" % fname)

                        #if link[0] in ["/", "\\"]:
                        #    link = link[1:]

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
                if "attachments" in chall and len(chall["attachments"]) > 0:

                    if not files_header:
                        chall_readme.write("## Files\n\n")

                    challFiles = os.path.join(challDir, "files")
                    os.makedirs(challFiles, exist_ok=True)

                    for attachment in chall["attachments"]:

                        # Fetch file from remote server
                        f_url = attachment['url']
                        F = S.get(f_url, stream=True, verify=VERIFY_SSL_CERT)

                        fname = slugify(attachment['name'])
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

                    chall_path = "%s/%s/" % (slugify(chall['category'], isdir=True), slugify(chall['name'], isdir=True))
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
        if len(failed_to_download_links) > 0:
            logging.warning("Warning, failed to download some files.")
            for ccategory, cname, link in failed_to_download_links:
                logging.warning("    %s > %s : %s" % (ccategory, cname, link))

if __name__ == "__main__":
    main(sys.argv[1:])
