import requests
import re
import yaml
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

def decode_resp_text(resp):
    """
    解码response包
    param: resp
    return: content
    """
    content = resp.content
    if not content:
        return str('')
    try:
        # 先尝试用utf-8严格解码
        content = str(content, encoding='utf-8', errors='strict')
    except (LookupError, TypeError, UnicodeError):
        try:
            # 再尝试用gb18030严格解码
            content = str(content, encoding='gb18030', errors='strict')
        except (LookupError, TypeError, UnicodeError):
            # 最后尝试自动解码
            content = str(content, errors='replace')
    return content

def main(url):
    p = urlparse(url)
    url = p.scheme + '://' + p.netloc + '/sssssssssssss'
    result = []
    with open('error.yaml','r',encoding='utf-8')as f:
        rules = yaml.safe_load(f.read())
    r = requests.get(url,verify=False)
    content = decode_resp_text(r)
    for rule in rules.values():
        if regVersion(content,rule):
            result.append(regVersion(content,rule))
    return result


def regVersion(content,rule):
    version = ''
    if len(rule) >= 2:
        for r in rule:
            if re.findall(r,content,re.I):
                version = version + ' ' + re.findall(r,content,re.I)[0]
        return version.strip()
    else:
        if re.findall(rule[0],content,re.I):
            version = re.findall(rule[0],content,re.I)[0]
            return version.strip()
    return None

if __name__ == '__main__':
    url = 'https://xss.yt/'
    result = main(url)
    print(result)