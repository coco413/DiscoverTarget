# -*- coding:utf-8 -*-
# !/usr/bin/env python

import re
import sys
import json
import fofa
import shodan
import optparse
import requests
import chardet
import datetime
import traceback
import gevent.monkey
from lxml import etree
from bs4 import BeautifulSoup
from gevent.threadpool import ThreadPool

reload(sys)
sys.setdefaultencoding('utf-8')
requests.packages.urllib3.disable_warnings()
gevent.monkey.patch_all()


class TargetCollect(object):
    def __init__(self, info):
        self.pool = ThreadPool(30)
        self.page = 80
        self.headers = {
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, sdch, br',
            'Accept-Language': 'zh-CN,zh;q=0.8',
        }
        self.urls_result = set()
        self.ips_result = set()
        self.ips_filename = "IP.txt"
        self.urls_filename = "URL.txt"
        self.proxy = {
            'http': 'http://127.0.0.1:1080',
            'https': 'http://127.0.0.1:1080'
        }

        self.shodan_url = "https://api.shodan.io/shodan/host/search?query=apache&key=MM72AkzHXdHpC8iP65VVEEVrJjp7zkgd"
        self.shodan_token = "XHSWncMjN6MEyekECTMcOeoEocl6VO2q"
        self.shodan_keyword = info['shodan']

        self.censys_url = "https://censys.io/api/v1/search/ipv4"
        self.censys_api_id = "9b611dbd-366b-41b1-a50e-1a024004609f"
        self.censys_secret = "wAUW4Ax9uyCkD7JrgS1ItJE5nHQD5DnR"
        self.censys_keyword = info['censys']

        self.fofa_email = "xxx@xxx.com"
        self.fofa_token = "xxxx"
        self.fofa_keyword = info['fofa']

        self.zoomeye_url = "https://api.zoomeye.org/host/search?page={}&query={}"
        self.zoomeye_user = "xxx@xx.com"
        self.zoomeye_pass = "xxx"
        self.zoomeye_keyword = info['zoomeye']
        self.zoomeye_pool = ThreadPool(10)

        self.baidu_url = "http://www.baidu.com/s?wd={}&pn={}0"
        self._360_url = "https://www.so.com/s?q={}&pn={}&fr=so.com"
        self.google_url = "https://www.google.com/search?q={}&safe=strict&start={}"
        self.keyword = info['b3g']

    def Shodan(self):
        try:
            api = shodan.Shodan(self.shodan_token)
            services = api.search(self.shodan_keyword)
            for service in services['matches']:
                print "[\033[0;39;40mShodan\033[0m] {}".format(service["ip_str"] + ":" + str(service["port"]))
                self.ips_result.add(service["ip_str"] + ":" + str(service["port"]))
        except:
            print "[\033[0;35;40mShodan\033[0m] Error"
            pass

    def Censys(self):
        try:
            r = requests.post(self.censys_url, auth=(self.censys_api_id, self.censys_secret),
                              json={"query": self.censys_keyword}, headers=self.headers, verify=False, timeout=15)
            json_data = r.json()
            for service in json_data["results"]:
                for i in service['protocols']:
                    port = re.sub("\D", "", i)
                    print "[\033[0;31;40mCensys\033[0m] {}".format(service["ip"] + ":" + port)
                    self.ips_result.add(service["ip"] + ":" + port)
        except:
            print "[\033[0;35;40mCensys\033[0m] Error"
            pass

    def Fofa(self, page=2):
        try:
            client = fofa.Client(self.fofa_email, self.fofa_token)
            for page in xrange(1, page):
                data = client.get_data(self.fofa_keyword, page=page, fields="ip,port")
                for ip, port in data["results"]:
                    print "[\033[0;32;40mFofa\033[0m] {}".format(ip + ":" + str(port))
                    self.ips_result.add(ip + ":" + str(port))
        except:
            print "[\033[0;35;40mFofa\033[0m] Error"
            pass

    def Zoomeye(self, page):
        def get_token(zoomeye_user, zoomeye_pass):
            try:
                data = {
                    "username": zoomeye_user,
                    "password": zoomeye_pass
                }
                data_encoded = json.dumps(data)
                data = requests.post(url='https://api.zoomeye.org/user/login', data=data_encoded)
                return json.loads(data.text)['access_token']
            except:
                pass
                print "[\033[0;35;40mZoomeye Token\033[0m] Error"

        try:
            token = get_token(self.zoomeye_user, self.zoomeye_pass)
            if not token:
                return
            r = requests.get(
                url="https://api.zoomeye.org/host/search?page={}&query={}".format(str(page), self.zoomeye_keyword),
                headers={'Authorization': 'JWT ' + token}, verify=False, timeout=15)
            data = json.loads(r.text)
            for i in data['matches']:
                print "[\033[0;34;40mZoomeye\033[0m] {}".format(i['ip'] + ':' + str(i['portinfo']['port']))
                self.ips_result.add(i['ip'] + ':' + str(i['portinfo']['port']))
        except:
            print "[\033[0;35;40mZoomeye\033[0m] Error"
            pass

    def Baidu(self, page):
        try:
            base_url = self.baidu_url.format(str(self.keyword), str(page))
            r = requests.get(base_url, headers=self.headers, verify=False, timeout=15)
            p = etree.HTML(r.content)
            tags = p.xpath(u'//a[@class="c-showurl"]')
            for tag in tags:
                r = requests.get(tag.get('href'), headers=self.headers, verify=False, timeout=15)
                soup = BeautifulSoup(r.content, 'html.parser')
                chardet.detect(r.content)
                title = soup.title.string if soup.title.string else ''
                if r.url and r.url not in self.urls_result:
                    print "[\033[0;36;40mBaidu\033[0m] {}\t{}".format(r.url, title)
                    self.urls_result.add(r.url)
        except:
            # print "[\033[0;35;40mBaidu\033[0m] Error"
            pass

    def _360(self, page):
        try:
            base_url = self._360_url.format(str(self.keyword), str(page))
            r = requests.get(base_url, headers=self.headers, verify=False, timeout=15)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.select('li.res-list > h3 > a'):
                r = requests.get(a['href'], headers=self.headers, verify=False, timeout=15)
                url = re.findall("URL='(.*?)'", r.text)[0] if re.findall("URL='(.*?)'",
                                                                         r.text) else r.url
                soup = BeautifulSoup(r.content, 'html.parser')
                chardet.detect(r.content)
                title = soup.title.string if soup.title.string else ''
                if url and url not in self.urls_result:
                    print "[\033[0;37;40m360\033[0m] {}\t{}".format(url, title)
                    self.urls_result.add(url)
        except:
            # print "[\033[0;35;40m360\033[0m] Error"
            pass

    def Google(self, page=2):
        try:
            for i in xrange(0, 10 * page, 10):
                base_url = self.google_url.format(self.keyword, str(i))
                r = requests.get(base_url, headers=self.headers, timeout=15)
                soup = BeautifulSoup(r.text, "html.parser")
                for j in soup.select('div.g > h3.r > a[href^="/url"]'):
                    url = j.get('href').replace('/url?q=', '')
                    print "[\033[0;40;40m360\033[0m] {}".format(url)
                    self.urls_result.add(url)
        except:
            # print "[\033[0;35;40m360\033[0m] Error"
            pass

    def main(self):
        try:
            if self.keyword:
                self.pool.map(self.Baidu, xrange(self.page))
                self.pool.join()
                self.pool.map(self._360, xrange(self.page))
                self.pool.join()
                self.Google()
            if self.zoomeye_keyword:
                self.zoomeye_pool.map(self.Zoomeye, xrange(self.page))
                self.zoomeye_pool.join()

            if self.shodan_keyword: self.Shodan()
            if self.fofa_keyword: self.Fofa()
            if self.censys_keyword: self.Censys()

            if self.ips_result:
                print "[+] Found [{}] ips".format(len(self.ips_result))
                with open(self.ips_filename, "w") as f:
                    for ip in self.ips_result:
                        f.write(ip.strip() + "\n")
            if self.urls_result:
                print "[+] Total Found [{}] urls".format(len(self.urls_result))
                with open(self.urls_filename, "w") as f:
                    for url in self.urls_result:
                        f.write(url.strip() + "\n")
        except:
            traceback.print_exc()


if __name__ == "__main__":
    banner = """
      _____  _                          _______                   _   
     |  __ \(_)                        |__   __|                 | |  
     | |  | |_ ___  ___ _____   _____ _ __| | __ _ _ __ __ _  ___| |_ 
     | |  | | / __|/ __/ _ \ \ / / _ \ '__| |/ _` | '__/ _` |/ _ \ __|
     | |__| | \__ \ (_| (_) \ V /  __/ |  | | (_| | | | (_| |  __/ |_ 
     |_____/|_|___/\___\___/ \_/ \___|_|  |_|\__,_|_|  \__, |\___|\__|
                                                        __/ |         
                                                       |___/         
                                        Coded By Coco413 (v1.0 RELEASE) 
    """
    parser = optparse.OptionParser(
        usage=banner,
        version='%prog v1.0',
        epilog='Example: python DiscoverTarget.py -S Apache-Tomcat -F app="Apache-Tomcat" -Z app:"Apache-Tomcat" -C Apache-Tomcat -B Powered by Discuz',
    )
    parser.add_option('-S', '--shodan', type="string", dest="shodan", default='', help="space search use shodan")
    parser.add_option('-F', '--fofa', type="string", dest="fofa", default='', help="space search in fofa")
    parser.add_option('-Z', '--zoomeye', type="string", dest="zoomeye", default='', help="space search use zoomeye")
    parser.add_option('-C', '--censys', type="string", dest="censys", default='', help="space search use censys")
    parser.add_option('-B', '--b3g', type="string", dest="b3g", default='',
                      help="traditional search use baidu 360 google")
    (options, args) = parser.parse_args()
    if options.shodan or options.fofa or options.zoomeye or options.censys or options.b3g:
        keyword = {
            'shodan': options.shodan,
            'fofa': options.fofa,
            'zoomeye': options.zoomeye,
            'censys': options.censys,
            'b3g': options.b3g
        }
        try:
            hand = TargetCollect(keyword)
            start = datetime.datetime.now()
            hand.main()
            print "[+] Total use [{}] s".format((datetime.datetime.now() - start).seconds)
        except KeyboardInterrupt:
            print "[+] Ctrl + C Exit..."
            sys.exit(0)
    else:
        print "[+] Error please input -h to help"
        sys.exit(1)
