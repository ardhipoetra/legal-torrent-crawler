import scrapy
import urllib2
import re
import time

class MininovaSpider(scrapy.Spider):
    name = "mininova"

    def start_requests(self):
        for i in xrange(1, 10):
            yield scrapy.Request(url="http://www.mininova.org/cat-list/%d/leech" %i, callback=self.parse)

    def parse(self, response):
        page = response.url.split("/")[-1]
        self.log("Open %s" %(response.url))

        for link in response.css(".dl"):
            dl = link.xpath("@href").extract_first()
            dl_link = response.urljoin(dl)

            self.log("Download:%s" %(dl_link))

            try:
                req = urllib2.Request(urllib2.quote(dl_link,':/'))
                req.add_header('Accept-Language', 'en-US')
                f = urllib2.urlopen(dl_link)

                time.sleep(2)

                content = f.info().dict["content-disposition"]
                filename = re.search(r'filename="(.*)"', content).group(1)

                filename = filename.replace(" ", "_")

                data = ''
                chunk = f.read()
                while chunk:
                    data += chunk
                    chunk = f.read()

                with open("torrent_dir/%s.torrent" %filename, 'wb') as file_:
                    file_.write(data)
            except:
                self.log("Cannot retrieve %s" %dl_link)

        next_page = response.xpath("//a[contains(@title, 'Next page')]/@href").extract_first()

        if next_page is not None:
            next_page = response.urljoin(next_page)
            next_page_int = int(next_page.split("/")[-1])

            if next_page_int < 10:
                yield scrapy.Request(next_page, callback=self.parse)
