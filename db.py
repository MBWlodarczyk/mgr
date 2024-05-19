from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    ForeignKey,
    Boolean,
    Float,
    DateTime,
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.orm import sessionmaker
import logging
import requests
import ssl
import socket
import whois
from OpenSSL import crypto
import datetime
from sqlalchemy.orm import sessionmaker
from langdetect import detect_langs
from bs4 import BeautifulSoup
import logging
import tldextract
import time
from io import BytesIO

import pytesseract
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import uuid
import Config


logging.basicConfig(filename="scraper.log", level=logging.INFO)

Base = declarative_base()

class bad_urls(Base):
    __tablename__ = "bad_urls"
    id = Column(Integer, primary_key=True)
    Url = Column(String)

class Domain(Base):
    __tablename__ = "domains"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.now())
    domain = Column(String)
    urls = relationship("Url", back_populates="domain")
    whois_txt = Column(String)
    language = Column(String)
    pl_prob = Column(Float)
    # create base on this {'version': 3, 'serialNumber': '04E1A77F4C1411AE28DA565817ED719E395C', 'notBefore': 'May  9 20:33:16 2024 GMT', 'notAfter': 'Aug  7 20:33:15 2024 GMT', 'subjectAltName': (('DNS', '*.im3q.icu'), ('DNS', 'im3q.icu')), 'OCSP': ('http://e1.o.lencr.org',), 'caIssuers': ('http://e1.i.lencr.org/',), 'issuer_countryName': 'US', 'issuer_organizationName': "Let's Encrypt", 'issuer_commonName': 'E1', 'subject_commonName': 'im3q.icu'}
    cert_serialNumber = Column(String)
    cert_version = Column(Integer)
    cert_signatureAlgorithm = Column(String)
    cert_subjectAltName = Column(String)
    cert_OCSP = Column(String)
    cert_caIssuers = Column(String)
    cert_issuer_countryName = Column(String)
    cert_issuer_organizationName = Column(String)
    cert_issuer_commonName = Column(String)
    cert_subject_commonName = Column(String)
    cert_age = Column(Integer)

    # whois info
    whois_age = Column(Integer)
    whois_registrar = Column(String)
    whois_country = Column(String)
    whois_organization = Column(String)

    urlscan_scanned_1 = Column(Boolean, default=False)


class Url(Base):
    __tablename__ = "urls"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.now())
    url = Column(String)
    content = Column(String)
    domain_id = Column(Integer, ForeignKey("domains.id"))
    domain = relationship("Domain", back_populates="urls")
    language = Column(String)
    pl_prob = Column(Float)
    screenshot_path = Column(String)
    ocr_text = Column(String)


# posgres on 192.168.50.172 with yourusername as username and yourpassword as password with db named yourdatabase
engine = create_engine(
    "postgresql://yourusername:yourpassword@192.168.50.172:5432/yourdatabase"
)
# drop the db
Base.metadata.drop_all(engine)
try:
    Base.metadata.create_all(engine)
except Exception as e:
    print(e)
    logging.error(e, exc_info=True)
    raise
Session = sessionmaker(bind=engine)


def save_domain(domain):
    # check if domain is already in the database
    session = Session()
    domain_db = session.query(Domain).filter(Domain.domain == domain).first()
    session.close()
    if domain_db is not None:
        return
    domain_db = Domain(domain=domain)
    try:
        details = get_certificate(domain)
        if details is not None:
            domain_db.cert_serialNumber = details[1]["serialNumber"]
            domain_db.cert_version = details[1]["version"]
            domain_db.cert_signatureAlgorithm = details[1]["signatureAlgorithm"]
            domain_db.cert_OCSP = details[1]["OCSP"][0]
            domain_db.cert_caIssuers = details[1]["caIssuers"][0]
            domain_db.cert_issuer_countryName = details[1]["issuer_countryName"]
            domain_db.cert_issuer_organizationName = details[1][
                "issuer_organizationName"
            ]
            domain_db.cert_issuer_commonName = details[1]["issuer_commonName"]
            domain_db.cert_subject_commonName = details[1]["subject_commonName"]
            # calcuate cert age by subtracting notBefore and now datetime
            now = datetime.datetime.now()
            notBefore = datetime.datetime.strptime(
                details[1]["notBefore"], "%b %d %H:%M:%S %Y %Z"
            )
            domain_db.cert_age = (now - notBefore).days

        else:
            logging.error("Failed to get certificate for domain: %s" % domain)
            return
    except Exception as e:
        logging.error("Failed to get certificate for domain: %s" % domain)
        return
    try:
        whois_info = get_whois_info(domain)
        if whois_info is not None:
            domain_db.whois_txt = whois_info.text
            domain_db.whois_registrar = whois_info.registrar
            domain_db.whois_country = whois_info.country
            domain_db.whois_organization = whois_info.organization
            # calculate whois age by subtracting creation date and now datetime
            now = datetime.datetime.now()
            creation_date = whois_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            domain_db.whois_age = (now - creation_date).days
        else:
            logging.error("Failed to get whois info for domain: %s" % domain)
            return
    except Exception as e:
        logging.error("Failed to get whois info for domain: %s" % domain)
        return

    try:
        domain_db.language, domain_db.pl_prob = detect_language("https://" + domain)
    except Exception as e:
        logging.error("Failed to detect language for domain: %s" % domain)
        domain_db.language = None

    try:
        with Session() as session:
            session.add(domain_db)
            session.commit()
    except Exception as e:
        logging.error(e, exc_info=True)
        return


def save_url_lang_check(url):
    # check language and pl probability
    with Session() as session:
        url_db = session.query(Url).filter(Url.url == url).first()
        if url_db is not None:
            return
        # check bad urls
        bad_url = session.query(bad_urls).filter(bad_urls.Url == url).first()
        if bad_url is not None:
            return

    language, pl_prob = detect_language(url)
    if language is None:
        return
    if pl_prob is None:
        return
    # if lanuage is pl or prob is higher than 0.5 save url
    if language == "pl" or pl_prob > 0:
        save_url(url)
    else:
        # save url to bad urls
        session = Session()
        bad_url = bad_urls(Url=url)
        session.add(bad_url)
        session.commit()

def save_url(url):
    # check if url is already in the database
    with Session() as session:
        url_db = session.query(Url).filter(Url.url == url).first()
    if url_db is not None:
        return

    # Get domain from url using libraries
    extracted = tldextract.extract(url)
    if extracted.subdomain:
        domain_with_subdomains = (
            f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
        )
    else:
        domain_with_subdomains = f"{extracted.domain}.{extracted.suffix}"

    # Check if domain is already in the database
    session = Session()
    domain = (
        session.query(Domain).filter(Domain.domain == domain_with_subdomains).first()
    )
    session.close()
    if domain is None:
        save_domain(domain_with_subdomains)
        # get domain object
        session = Session()
        domain = (
            session.query(Domain)
            .filter(Domain.domain == domain_with_subdomains)
            .first()
        )
        session.close()

    # get url content and save it using requests

    r = requests.get(url, verify=False)
    if r.status_code == 200:
        content = r.text
    else:
        content = None


    # get screenshot and ocr text
    ocr_text,screenshot_path,language,pl_prob = ocr_from_url(url)

    try:
        url = Url(
            url=url, content=content, domain=domain, language=language, pl_prob=pl_prob, screenshot_path=screenshot_path, ocr_text=ocr_text
        )
        session = Session()
        session.add(url)
        session.commit()
        session.close()
    except Exception as e:
        logging.error(e, exc_info=True)
        raise


def get_certificate(domain):
    try:
        # Establish a secure connection with the domain
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Retrieve the certificate
                cert = ssock.getpeercert()

                # Extract certificate information
                cert_info = {
                    "version": cert["version"],
                    "serialNumber": cert["serialNumber"],
                    "notBefore": cert["notBefore"],
                    "notAfter": cert["notAfter"],
                    "signatureAlgorithm": cert.get("signatureAlgorithm", None),
                    "subjectAltName": cert.get("subjectAltName", None),
                    "OCSP": cert.get("OCSP", None),
                    "caIssuers": cert.get("caIssuers", None),
                    "issuer_countryName": None,
                    "issuer_organizationName": None,
                    "issuer_commonName": None,
                    "subject_commonName": None,
                }

                # Extract issuer fields
                for field in cert["issuer"]:
                    field_name, field_value = field[0]
                    cert_info[f"issuer_{field_name}"] = field_value

                # Extract subject fields
                for field in cert["subject"]:
                    field_name, field_value = field[0]
                    cert_info[f"subject_{field_name}"] = field_value

                return None, cert_info
    except Exception as e:
        return None, {"error": str(e)}


def detect_language(url):
    try:
        # Fetch the web page content
        response = requests.get(url, verify=False)
        response.raise_for_status()  # Raise an exception for non-200 status codes
        # parse text so that it can be detected and not the html tags using beautify soup
        # extract text from html
        soup = BeautifulSoup(response.text, "html.parser")
        response = soup.get_text()
        # Detect the language of the content
        language_array = detect_langs(response)
        # get the most probable language
        language = language_array[0].lang
        pl_prob = 0
        for langs in language_array:
            # if there is pl language in the array return its prob
            if langs.lang == "pl":
                pl_prob = langs.prob
        return language, pl_prob
    except Exception as e:
        print(f"Error fetching or detecting language: {e}")
        return None, None
    
def detect_language_text(text):
    try:
        # Fetch the web page content
        language_array = detect_langs(text)
        # get the most probable language
        language = language_array[0].lang
        pl_prob = 0
        for langs in language_array:
            # if there is pl language in the array return its prob
            if langs.lang == "pl":
                pl_prob = langs.prob
        return language, pl_prob
    except Exception as e:
        print(f"Error fetching or detecting language: {e}")
        return None, None


def get_whois_info(domain):
    try:
        # Query WHOIS information for the domain
        info = whois.whois(domain)

        # Extract relevant information

        return info
    except Exception as e:
        return {"error": str(e)}


def ocr_from_url(url):
    try:
        # Set up Selenium and open the webpage
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.get(url)

        # Give the page some time to load
        time.sleep(2)
        total_width = driver.execute_script("return document.body.scrollWidth")
        total_height = driver.execute_script("return document.body.scrollHeight")
        driver.set_window_size(total_width, total_height)

        # Take a screenshot of the webpage
        screenshot = driver.get_screenshot_as_png()

        #generate uuid for the screenshot
        uuid_text = uuid.uuid4().hex

        # Close the browser
        driver.quit()

        # Open the screenshot image
        image = Image.open(BytesIO(screenshot))

        # Perform OCR on the image
        text = pytesseract.image_to_string(image)
        # get rid of nul char in text
        text = text.replace("\x00", "")

        # detect language of the text and pl prob
        language, pl_prob = detect_language_text(text)
    except Exception as e:
        print(e)    
    image.save(Config.screenshots_path + uuid_text + ".png")
    # if pl or pl prob is higher than 0 save the screenshot
    if language == "pl" or pl_prob > 0:
        image.save(Config.screenshots_path + uuid_text + ".png")
    print(text,uuid_text,language,pl_prob)
    return text,uuid_text,language,pl_prob


