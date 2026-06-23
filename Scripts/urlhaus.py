import os
import re
import csv
import ipaddress
from urllib.parse import urlparse
import requests

zdroje = {
    "URLhaus": "https://urlhaus.abuse.ch/downloads/text/",
    "ThreatFox": "https://threatfox.abuse.ch/downloads/hostfile/",
    "PhishTank": "http://data.phishtank.com/data/online-valid.csv"
}

unikatne_riadky = set()

port_regex = re.compile(r":\d{1,5}")

hostname_regex = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)

headers = {
    "User-Agent": "Mozilla/5.0"
}


def valid_hostname(host):
    host = host.lower().strip()

    if not host:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    return bool(hostname_regex.match(host))


print("Pracovný adresár:", os.getcwd())

for nazov_zdroja, url in zdroje.items():
    print(f"Sťahujem {nazov_zdroja}...")

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=45
        )

        if response.status_code != 200:
            print(
                f"Chyba pri sťahovaní {nazov_zdroja}: "
                f"HTTP {response.status_code}"
            )
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

                if not url_na_parsovanie:
                    continue

                try:
                    parsed = urlparse(url_na_parsovanie)

                    domena = parsed.netloc.lower()
                    cesta = parsed.path

                    if domena.startswith("www."):
                        domena = domena[4:]

                    if parsed.query:
                        cesta += "?" + parsed.query

                    if parsed.fragment:
                        cesta += "#" + parsed.fragment

                    if not cesta:
                        cesta = "/"

                    domena = port_regex.sub("", domena)

                    if not valid_hostname(domena):
                        continue

                    unikatne_riadky.add(
                        f"{domena},{cesta},PhishTank"
                    )

                    pocet_z_tohto_zdroja += 1

                except Exception:
                    continue

        else:

            for riadok in riadky_textu:

                riadok = riadok.strip()

                if not riadok:
                    continue

                if riadok.startswith("#"):
                    continue

                if riadok.startswith(";"):
                    continue

                if nazov_zdroja == "ThreatFox":

                    if not riadok.startswith("127.0.0.1"):
                        continue

                    riadok = (
                        riadok
                        .replace("127.0.0.1", "")
                        .strip()
                    )

                try:

                    if not riadok.startswith(
                        ("http://", "https://")
                    ):
                        url_na_parsovanie = (
                            "http://" + riadok
                        )
                    else:
                        url_na_parsovanie = riadok

                    parsed = urlparse(url_na_parsovanie)

                    domena = parsed.netloc.lower()
                    cesta = parsed.path

                    if domena.startswith("www."):
                        domena = domena[4:]

                    if parsed.query:
                        cesta += "?" + parsed.query

                    if parsed.fragment:
                        cesta += "#" + parsed.fragment

                    if not cesta:
                        cesta = "/"

                    domena = port_regex.sub("", domena)

                    if not valid_hostname(domena):
                        continue

                    unikatne_riadky.add(
                        f"{domena},{cesta},{nazov_zdroja}"
                    )

                    pocet_z_to_this_source += 1

                except Exception:
                    continue

        print(
            f"-> Spracované zo {nazov_zdroja}: "
            f"{pocet_z_tohto_zdroja}"
        )

    except Exception as e:
        print(
            f"Zlyhalo spojenie so "
            f"{nazov_zdroja}: {e}"
        )

os.makedirs("Lists", exist_ok=True)

vystupny_subor = "Lists/urlhaus_urls.txt"

if len(unikatne_riadky) > 100:

    with open(
        vystupny_subor,
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        f.write("hostname,path,comment\n")

        for riadok in sorted(unikatne_riadky):
            f.write(riadok + "\n")

    print(
        f"HOTOVO - uložených "
        f"{len(unikatne_riadky)} záznamov"
    )

else:

    print(
        f"CHYBA - iba "
        f"{len(unikatne_riadky)} záznamov"
    )

    exit(1)
