import scrapy
import urllib

class EtreeSpider(scrapy.Spider):
    name = "etree"

    def start_requests(self):
        urls = [
            'http://bt.etree.org/index.php?searchzz&sort=leechers&page=0'
        ]
        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        page = response.url.split("=")[-1]
        self.log("Open %s" %(response.url))

        for link in response.xpath("//a[contains(@href, '.torrent')]/@href"):
            dl = link.extract()
            name = link.re(r'.*/.*/(.*)')

            dl_link = "http://bt.etree.org/%s" %(dl)
            self.log("Download:%s filename:%s" %(dl_link, name))
            try:
                urllib.urlretrieve(dl_link, "torrent_dir/%s" %name)
            except:
                self.log("Cannot retrieve %s" %dl_link)

        next_page = int(page) + 50
        if next_page is not None and next_page < 400:
            next_page = response.urljoin("index.php?searchzz&sort=leechers&page=%d" %next_page)
            yield scrapy.Request(next_page, callback=self.parse)
