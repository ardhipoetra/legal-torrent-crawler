import scrapy
import urllib
import re
import time

class LegitSpider(scrapy.Spider):
    name = "legittorrent"

    def start_requests(self):
        yield scrapy.Request(url="http://www.legittorrents.info/index.php?page=torrents&active=1&order=6&by=2&pages=1",
                             callback=self.parse)

    def parse(self, response):
        page = response.url.split("=")[-1]
        self.log("Open %s" %(response.url))

        for link in response.xpath("//a[contains(@href, '.torrent')]/@href"):
            dl = link.extract()
            name = link.re(r'f=(.*)')[0]

            dl_link = response.urljoin(dl)

            self.log("Download:%s filename:%s" %(dl_link, name))
            # try:
            urllib.urlretrieve(dl_link, "torrent_dir/%s" %name)
            time.sleep(2)
            # except:
            #     self.log("Cannot retrieve %s" %dl_link)

        next_page = response.css(".pager").xpath("a[contains(., '>')]/@href").extract_first()
        if next_page is not None:
            next_page = response.urljoin(next_page)
            yield scrapy.Request(next_page, callback=self.parse)
