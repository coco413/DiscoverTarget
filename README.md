### 0x00 简介
尽可能花更少的时间,使用All in one工具收集更多的信息-URL采集。
集360、百度、谷歌、Shodan、Zoomeye、Censys、Fofa于一体一键运行获取目标URL、IP等信息。


### 0x01 使用
___
- 1.下载
```
git git@github.com:coco413/DiscoverTarget.git
cd DiscoverTarget
pip install shodan fofa gevent bs4 lxml
```
- 2.配置
```
self.shodan_token = "xxxx"

self.censys_api_id = "xxxx"
self.censys_secret = "xxxxx"

self.fofa_email = "xxxx@xxx.com"
self.fofa_token = "xxxxx"

self.zoomeye_user = "xxx@xxx.com"
self.zoomeye_pass = "xxxxx"
self.zoomeye_keyword = info['zoomeye']
self.zoomeye_pool = ThreadPool(10)
```
- 3.运行
```
运行环境：python 2.7 Mac
Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -S SHODAN, --shodan=SHODAN
                        space search use shodan
  -F FOFA, --fofa=FOFA  space search in fofa
  -Z ZOOMEYE, --zoomeye=ZOOMEYE
                        space search use zoomeye
  -C CENSYS, --censys=CENSYS
                        space search use censys
  -B B3G, --b3g=B3G     traditional search use baidu 360 google

Example: python DiscoverTarget.py -S Apache-Tomcat -F app="Apache-Tomcat" -Z
app:"Apache-Tomcat" -C Apache-Tomcat -B Powered by Discuz

python DiscoverTarget.py -B inurl:.action  URL采集
python DiscoverTarget.py -Z app:"Apache-Tomcat" 使用zoomeye IP采集
python DiscoverTarget.py -S Apache-Tomcat -F app="Apache-Tomcat" -Z
app:"Apache-Tomcat" -C Apache-Tomcat -B Powered by Discuz 一键扫描

```
- 4.截图
![url](https://s1.ax1x.com/2018/05/07/CUy3CT.png)
![ip](https://s1.ax1x.com/2018/05/07/CUybrj.jpg)


### 0x02 其他
- 1.免费shodan api只能获取到1000个结果,并且不能使用高级语法。
- 2.普通Fofa获取的数据页不能获取很多,因此page=2,高级用户可以调节。
- 3.URL采集线程池、输出、页面数等因为基本不修改所以没加入参数,需要修改直接修改。
- 4.出现Error情况大多是网络、API限制等问题,换账号、检查语法，调低线程池以及requests加点代理。
- 5.Tools目录存放Win下URL采集工具,辅助目标收集。