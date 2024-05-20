from db import engine, Domain, Url, save_domain,save_url,Session,save_url_lang_check
import requests
import Config
import logging
import datetime

from concurrent.futures import ThreadPoolExecutor

# configure logger to file
logging.basicConfig(filename='scraper.log', level=logging.INFO)




def get_domains_from_cert_pl():
    count = 0
    try:
        
        r = requests.get(Config.cert_link, headers=Config.headers, timeout=Config.timeout)
        if r.status_code == 200:
            with ThreadPoolExecutor(max_workers=10) as executor:
                domains = r.json()
                for domain in domains:
                    # create now - rescan_time datetime object, convert domain insert date to datetime object and compare
                    now = datetime.datetime.now() - datetime.timedelta(minutes=Config.rescan_time)
                    domain['InsertDate'] = datetime.datetime.strptime(domain['InsertDate'], '%Y-%m-%dT%H:%M:%S')
                    if domain['InsertDate'] > now:
                        # do it concurently
                            count += 1
                            executor.submit(save_domain,domain["DomainAddress"])

                        # wait for all
                executor.shutdown(wait=True)
        logging.info("Inserted %s domains" % count)
    except Exception as e:
        logging.error(e, exc_info=True)
        raise

def get_urls_from_domains():

    with Session() as session:
        # get url count before
        url_count = session.query(Url).count()
        with ThreadPoolExecutor(max_workers=10) as executor:
        # get not scnaned domains
            domains = session.query(Domain).filter(Domain.urlscan_scanned_1 == False).all()

            for domain in domains:
                # do it concurently
                executor.submit(scan_us,domain.domain)
                domain.urlscan_scanned_1 = True
                session.commit()
            # wait for all
            executor.shutdown(wait=True)
        # get url count after
        url_count_after = session.query(Url).count()
        logging.info("Inserted %s urls" % (url_count_after - url_count))



def scan_us(domain):
    try:
        r = requests.get('https://urlscan.io/api/v1/search/?q=domain:%s' % domain, headers=Config.urlscan_headers, timeout=Config.timeout)
        if r.status_code == 200:
            urls = r.json()
            with ThreadPoolExecutor(max_workers=10) as executor:
                for url in urls['results']:
                    # do it concurently
                    executor.submit(save_url,url["page"]["url"])
                # wait for all
                executor.shutdown(wait=True)
    except Exception as e:
        logging.error(e, exc_info=True)
        raise

def get_urls_from_openphish():
    try:
        r = requests.get('https://openphish.com/feed.txt', headers=Config.headers, timeout=Config.timeout)
        if r.status_code == 200:
            urls = r.text.split('\n')
            with ThreadPoolExecutor(max_workers=10) as executor:
                for url in urls:
                    # do it concurently
                    executor.submit(save_url_lang_check,url)
                # wait for all
                executor.shutdown(wait=True)
    except Exception as e:
        logging.error(e, exc_info=True)
        raise

def get_urls_from_phishhunt():
    try:
        r = requests.get('https://phishunt.io/feed.txt', headers=Config.headers, timeout=Config.timeout)
        if r.status_code == 200:
            urls = r.text.split('\n')
            with ThreadPoolExecutor(max_workers=10) as executor:
                for url in urls:
                    # do it concurently
                    executor.submit(save_url_lang_check,url)
                # wait for all
                executor.shutdown(wait=True)
    except Exception as e:
        logging.error(e, exc_info=True)
        raise

def get_urls_from_phishtank():
    try:
        r = requests.get('https://data.phishtank.com/data/online-valid.json', headers=Config.headers, timeout=Config.timeout)
        if r.status_code == 200:
            urls = r.json()
            with ThreadPoolExecutor(max_workers=10) as executor:
                for url in urls:
                    # do it concurently
                    executor.submit(save_url_lang_check,url)
                # wait for all
                executor.shutdown(wait=True)
    except Exception as e:
        logging.error(e, exc_info=True)
        raise


def get_urls_from_phishfindr():
    try:
        r = requests.get('https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt', headers=Config.headers, timeout=Config.timeout)
        if r.status_code == 200:
            urls = r.json()
            with ThreadPoolExecutor(max_workers=10) as executor:
                for url in urls:
                    # do it concurently
                    executor.submit(save_url_lang_check,url)
                # wait for all
                executor.shutdown(wait=True)
    except Exception as e:
        logging.error(e, exc_info=True)
        raise

def get_urls_from_urlscan():
    try:
        r = requests.get('https://urlscan.io/api/v1/search/?q=task.tags:%22%23phishing%22', headers=Config.urlscan_headers, timeout=Config.timeout)
        if r.status_code == 200:
            urls = r.json()
            with ThreadPoolExecutor(max_workers=10) as executor:
                for url in urls['results']:
                    # do it concurently
                    executor.submit(save_url,url["page"]["url"])
                # wait for all
                executor.shutdown(wait=True)
    except Exception as e:
        logging.error(e, exc_info=True)
        raise

if __name__ == '__main__':
    logging.info("Starting scraper "+str(datetime.datetime.now()))
    logging.info("Getting domains from cert.pl")
    try:
        get_domains_from_cert_pl()
        logging.info("Getting urls from domains")
        get_urls_from_domains()
    except Exception as e:
        logging.error(e, exc_info=True)
    try:
        logging.info("Getting urls from openphish")
        get_urls_from_openphish()
    except Exception as e:
        logging.error(e, exc_info=True)
    try:
        logging.info("Getting urls from phishhunt")
        get_urls_from_phishhunt()
    except Exception as e:
        logging.error(e, exc_info=True)
    try:
        logging.info("Getting urls from phishtank")
        get_urls_from_phishtank()
    except Exception as e:
        logging.error(e, exc_info=True)
    try:
        logging.info("Getting urls from phishfindr")
        get_urls_from_phishfindr()
    except Exception as e:
        logging.error(e, exc_info=True)
    try:
        logging.info("Getting urls from urlscan")
        get_urls_from_urlscan()
    except Exception as e:
        logging.error(e, exc_info=True)
    logging.info("Ending scraper "+str(datetime.datetime.now()))

