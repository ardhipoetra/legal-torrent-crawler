import scrapy
import urllib
import re
import time

class LVoxSpider(scrapy.Spider):
    name = "librivox"
    limit = 10

    def start_requests(self):
        yield scrapy.Request(url="https://librivox.org/api/feed/audiobooks/title/?offset=0&limit=100",
                             callback=self.parsexml)

    def parsexml(self, response):
        page = int(re.search(r'offset=([0-9]*)', response.url).group(1))/100
        self.log("Open %s" %(response.url))

        for link in response.xpath('//books/book/url_librivox/text()'):
            liblink = link.extract()

            self.log("Opening:%s" %(liblink))
            # try:
            yield scrapy.Request(url=liblink, callback=self.parse)
            # except:
            #     self.log("Cannot retrieve %s" %dl_link)

        next_page = (page + 1)
        if next_page < self.limit:
            next_page_link = response.urljoin("?offset=%d&limit=100" %(next_page * 100))
            yield scrapy.Request(next_page_link, callback=self.parsexml)


    def parse(self, response):
        self.log("Open %s" %(response.url))
        dl_link = response.css(".book-download-btn").xpath("//a[contains(@href,'.torrent')]/@href").extract_first()
        name = dl_link.split("/")[-1]
        self.log("Download:%s filename:%s" %(dl_link, name))
        try:
            urllib.urlretrieve(dl_link, "torrent_dir/%s" %name)
            time.sleep(1)
        except:
            self.log("Cannot retrieve %s" %dl_link)
