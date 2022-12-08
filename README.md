# Simple-CTFd-Downloader
A script to download challenges and files from CTFd instances.

## Usage

```
python download.py
    Main parameters:
        -u    The URL of the CTFd instance
        -n    The name of the event
        -o    The output directory where the challenges will be saved
    Authentication parameters (only one of them is needed):
        -t    An API token generated through an account's settings
        -c    An active session cookie for a connected account (value only), e.g. aabbccdd.abcd

    Example run:
        Download using API token
            python3 download.py -u http://ctf.url -n ctf_name -o ./ctf_name_files -t my_api_token
        Download using session cookie
            python3 download.py -u http://ctf.url -n ctf_name -o ./ctf_name_files -c the_value_of_the_session_cookie
        Download when there is open access
            python3 download.py -u http://ctf.url -n ctf_name -o ./ctf_name_files -c test
        Download from rCTF using Auth Token (beta)
            python3 download-rCTF.py -u http://ctf.url -n ctf_name -o ./ctf_name_files -t the_token_object_from_the_localstorage
```

## Setup
First download the git repo

```bash
git clone https://github.com/GramThanos/Simple-CTFd-Downloader.git
cd Simple-CTFd-Downloader
```

Then insall python requirements
```bash
pip install -r requirements.txt
```
Or for spesific python version
```bash
python3 -m pip install -r requirements.txt
```
