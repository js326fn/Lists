import os
import re
import csv
from urllib.parse import urlparse
import requests

zdroje = {
    "URLhaus": "https://urlhaus.abuse.ch/downloads/text/",
    "ThreatFox": "https://threatfox.abuse.ch/downloads/hostfile/",
    "PhishTank": "http://data.phishtank.com/data/online-valid.csv"
}

unikatne_riadky = set()
port_regex = re.compile(r":\d{1,5}")
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

print("Pracovný adresár:", os.getcwd())

for nazov_zdroja, url in zdroje.items():
    print(f"Sťahujem {nazov_zdroja}...")

    try:
        response = requests.get(url, headers=headers, timeout=45)

        if response.status_code != 200:
            print(f"Chyba pri sťahovaní {nazov_zdroja}: HTTP {response.status_code}")
            continue

        pocet_z_tohto_zdroja = 0
        riadky_textu = response.text.splitlines()

        if nazov_zdroja == "PhishTank":
            reader = csv.reader(riadky_textu)

            next(reader, None)

            for row in reader:
                if len(row) < 2:
                    continue

                url_na_parsovanie = row[1].strip()

                if not url_na_parsovanie or url_na_parsovanie.startswith("#"):
                    continue

                try:
                    parsed_url = urlparse(url_na_parsovanie)

                    domena = parsed_url.netloc
                    cesta = parsed_url.path

                    if domena.startswith("www."):
                        domena = domena[4:]

                    if parsed_url.query:
                        cesta += "?" + parsed_url.query

                    if parsed_url.fragment:
                        cesta += "#" + parsed_url.fragment

                    if not cesta:
                        cesta = "/"

                    cista_domena = port_regex.sub("", domena)
                    cista_cesta = port_regex.sub("", cesta)

                    unikatne_riadky.add(
                        f"{cista_domena},{cista_cesta},{nazov_zdroja}"
                    )

                    pocet_z_tohto_zdroja += 1

                except Exception:
                    continue

        else:
            for riadok in riadky_textu:
                riadok = riadok.strip()

                if not riadok or riadok.startswith(("#", ";")):
                    continue

                if nazov_zdroja == "ThreatFox":
                    if riadok.startswith("127.0.0.1"):
                        riadok = riadok.replace("127.0.0.1", "").strip()
                    else:
                        continue

                try:
                    url_na_parsovanie = riadok

                    if not url_na_parsovanie.startswith(("http://", "https://")):
                        url_na_parsovanie = "http://" + url_na_parsovanie

                    parsed_url = urlparse(url_na_parsovanie)

                    domena = parsed_url.netloc
                    cesta = parsed_url.path

                    if domena.startswith("www."):
                        domena = domena[4:]

                    if parsed_url.query:
                        cesta += "?" + parsed_url.query

                    if parsed_url.fragment:
                        cesta += "#" + parsed_url.fragment

                    if not cesta:
                        cesta = "/"

                    cista_domena = port_regex.sub("", domena)
                    cista_cesta = port_regex.sub("", cesta)

                    unikatne_riadky.add(
                        f"{cista_domena},{cista_cesta},{nazov_zdroja}"
                    )

                    pocet_z_tohto_zdroja += 1

                except Exception:
                    continue

        print(
            f"-> Úspešne spracované zo {nazov_zdroja}: {pocet_z_tohto_zdroja} riadkov"
        )

    except Exception as e:
        print(f"Zlyhalo spojenie so {nazov_zdroja}: {e}")

os.makedirs("Lists", exist_ok=True)

vystupny_subor = "Lists/urlhaus_urls.txt"

if len(unikatne_riadky) > 100:
    with open(vystupny_subor, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(unikatne_riadky)))

    print(f"\nHOTOVO")
    print(f"Zapísaných: {len(unikatne_riadky)} záznamov")
    print(f"Súbor: {vystupny_subor}")
else:
    print(f"\nCHYBA: Len {len(unikatne_riadky)} záznamov")
    exit(1)
