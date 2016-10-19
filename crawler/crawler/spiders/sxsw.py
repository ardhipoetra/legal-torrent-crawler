import scrapy
import urllib

class SxswSpider(scrapy.Spider):
    name = "sxsw"

    def start_requests(self):
        for i in xrange(2005,2017):
            yield scrapy.Request(url="http://www.sxswtorrent.com/%s" %i, callback=self.parse)

    def parse(self, response):
        page = response.url.split("=")[-1]
        self.log("Open %s" %(response.url))

        for link in response.xpath("//a[contains(@href, '.torrent')]/@href"):
            dl_link = link.extract()
            name = link.re(r'.*/.*/(.*)\.')[0]

            self.log("Download:%s filename:%s" %(dl_link, name))
            try:
                urllib.urlretrieve(dl_link, "torrent_dir/%s.torrent" %name)
            except:
                self.log("Cannot retrieve %s" %dl_link)
