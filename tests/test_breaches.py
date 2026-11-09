"""Breach feed: parsing, filtering, safety and merging, on RSS and Atom shapes."""
from datetime import datetime, timedelta, timezone

from app import breaches

NOW = datetime.now(timezone.utc)
RFC = lambda d: d.strftime("%a, %d %b %Y %H:%M:%S +0000")  # noqa: E731
OLD = NOW - timedelta(days=60)

LEAK_RSS = f"""<rss><channel>
<item><title>Argentine Healthcare Provider Swiss Medical Listed in Alleged 458K-Record Member Data Sale</title>
 <link>https://darkwebinformer.com/swiss-medical/</link><pubDate>{RFC(NOW)}</pubDate>
 <description>&lt;p&gt;A threat actor posted on a forum http://abcdefghij.onion/thread/1 offering data&lt;/p&gt;</description></item>
<item><title>Europol arrests suspect in fraud ring</title><link>https://darkwebinformer.com/europol/</link><pubDate>{RFC(NOW)}</pubDate></item>
<item><title>Sri Lankan telecom database allegedly leaked with 1.2 million customers</title>
 <link>https://darkwebinformer.com/lk-telco/</link><pubDate>{RFC(NOW - timedelta(days=1))}</pubDate></item>
<item><title>Onion only</title><link>http://xyz.onion/leak</link></item>
</channel></rss>""".encode()

NEWS_ATOM = f"""<feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Swiss Medical listed in alleged 458K record member data sale</title>
 <link rel="alternate" href="https://databreaches.net/swiss-medical-report/"/><updated>{NOW.isoformat()}</updated>
 <summary>Coverage of the claimed leak.</summary></entry>
<entry><title>Hospital notifies 23,685 patients of breach</title>
 <link href="https://databreaches.net/hospital/"/><published>{NOW.isoformat()}</published></entry>
</feed>""".encode()


def fake_get(url):
    if "darkwebinformer" in url and url.endswith("/rss/"):
        return LEAK_RSS
    if "databreaches.net" in url:
        return NEWS_ATOM
    raise OSError("offline")


def test_records_parser():
    assert breaches.records("Alleged 458K-Record Member Data Sale") == 458000
    assert breaches.records("23,685 fintech records and 326 KYC archives") == 23685
    assert breaches.records("1.2 million customers") == 1200000
    assert breaches.records("Version 2.5 released") is None


def test_collect_filters_dedupes_and_is_safe():
    status = {}
    hibp = [{"title": "Example Shop", "link": "https://haveibeenpwned.com/PwnedWebsites#ExampleShop",
             "added": NOW.strftime("%Y-%m-%d"), "count": 120000, "data": ["Email addresses"], "verified": True}]
    items = breaches.collect(fake_get, [], hibp, status)
    titles = [i["title"] for i in items]
    assert not any("Europol" in t for t in titles)                 # not a data-leak report
    assert not any(".onion" in i["link"] or ".onion" in i["summary"] for i in items)
    swiss = [i for i in items if "Swiss Medical" in i["title"]]
    assert len(swiss) == 1 and swiss[0]["also"] == ["DataBreaches.net"]   # same story from 2 sources merged
    assert swiss[0]["records"] == 458000 and swiss[0]["kind"] == "leak" and "alleged" in swiss[0]["tags"]
    lk = next(i for i in items if "Sri Lankan" in i["title"])
    assert lk["south_asia"] and lk["records"] == 1200000
    hosp = next(i for i in items if "Hospital" in i["title"])
    assert hosp["kind"] == "news" and hosp["records"] == 23685 and hosp["date"] == NOW.strftime("%Y-%m-%d")
    conf = next(i for i in items if i["kind"] == "confirmed")
    assert conf["records"] == 120000 and conf["tags"] == ["verified"]
    assert status["Dark-web leak reports"]["ok"] and status["Breach news"]["ok"]
    assert items == sorted(items, key=lambda i: i["date"], reverse=True)


def test_history_kept_when_feeds_fail_and_old_items_expire():
    first = breaches.collect(fake_get, [], [], {})
    old = {"title": "Ancient leak", "link": "https://x.example/old", "source": "X", "kind": "news",
           "date": OLD.strftime("%Y-%m-%d"), "summary": "", "records": None, "south_asia": False, "tags": []}
    status = {}
    def down(url):
        raise OSError("down")
    second = breaches.collect(down, first + [old], [], status)
    assert [i["link"] for i in second] == [i["link"] for i in first]  # kept from history, old one expired
    assert not status["Dark-web leak reports"]["ok"]
