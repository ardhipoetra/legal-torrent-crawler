import scrapy
import urllib

class LinuxTrackerSpider(scrapy.Spider):
    name = "ltracker"

    def start_requests(self):
        urls = [
            'http://linuxtracker.org/index.php?page=torrents&active=1&order=3&by=2&pages=1'
        ]
        for url in urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def parse(self, response):
        page = response.url.split("/")[-2]
        self.log("Open %s" %(response.url))

        for link in response.xpath("//a[contains(@title, 'View details')]"):
            ihash = link.re(r'id=\s*(.*)" ')[0]# if len(link.re(r'id=\s*(.*)" ')) > 1 else None
            name = link.re(r'View details: (.*)"')[0]# if len(re(r'View details: (.*)"')) > 1 else None

            name = name.replace(" ", "_")

            dl_link = "http://linuxtracker.org/download.php?id=%s&f=%s.torrent" %(ihash, name)
            self.log("Download:%s infohash:%s filename:%s" %(dl_link, ihash, name))
            try:
                urllib.urlretrieve(dl_link, "torrent_dir/%s.torrent" %name)
            except:
                self.log("Cannot retrieve %s" %dl_link)

        next_page = response.css(".pager").xpath("a[contains(., '>')]/@href").extract_first()
        if next_page is not None:
            next_page = response.urljoin(next_page)
            yield scrapy.Request(next_page, callback=self.parse)
