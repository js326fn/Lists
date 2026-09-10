import os
import re
import bz2
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, unquote

import requests


# ============================================================
# ZDROJE
# ============================================================

zdroje = {
    "URLhaus": "https://urlhaus.abuse.ch/downloads/text/",
    "ThreatFox": "https://threatfox.abuse.ch/downloads/hostfile/",
    "PhishTank": "http://data.phishtank.com/data/online-valid.xml.bz2",
}


# ============================================================
# NASTAVENIA
# ============================================================

unikatne_riadky = set()

# Odstránenie portu
port_regex = re.compile(r":\d{1,5}$")

# Povolené znaky v doméne
validna_domena_regex = re.compile(r"^[a-zA-Z0-9.-]+$")

# AWS Access Key ID
aws_access_key_regex = re.compile(
    r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"
)

# GitHub tokeny
github_token_regex = re.compile(
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b"
)

# Kandidát na AWS Secret Access Key.
#
# AWS secret má typicky 40 znakov z base64-like množiny.
# Čisté 40-znakové HEX hodnoty ignorujeme, pretože môže ísť napr.
# o SHA-1 hash, ktorý sa v malware URL vyskytuje bežne.
aws_secret_candidate_regex = re.compile(
    r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
)

hex_40_regex = re.compile(r"^[A-Fa-f0-9]{40}$")


# Simulácia normálneho prehliadača
headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


# Počítadlo záznamov zahodených kvôli možným secretom
pocet_odstranenych_secretov = 0


# ============================================================
# KONTROLA SECRETOV
# ============================================================

def obsahuje_secret(text):
    """
    Skontroluje, či text obsahuje potenciálny credential/token.

    URL sa najprv dekóduje, aby sa zachytili aj hodnoty
    zapísané napr. ako %2F, %2B, %3D atď.
    """

    try:
        decoded = unquote(text)
    except Exception:
        decoded = text

    # AWS Access Key ID
    if aws_access_key_regex.search(decoded):
        return True

    # GitHub token
    if github_token_regex.search(decoded):
        return True

    # Kandidát na AWS Secret Access Key
    for match in aws_secret_candidate_regex.finditer(decoded):
        kandidat = match.group(0)

        # SHA-1 hash nechceme považovať za AWS secret
        if hex_40_regex.fullmatch(kandidat):
            continue

        return True

    return False


# ============================================================
# PRIDANIE ZÁZNAMU
# ============================================================

def pridaj_zaznam(domena, cesta, komentar):
    """
    Bezpečne pridá záznam do výsledného setu.

    Ak obsahuje možný secret, celý záznam sa zahodí.
    """

    global pocet_odstranenych_secretov

    zaznam = f"{domena},{cesta},{komentar}"

    if obsahuje_secret(zaznam):
        pocet_odstranenych_secretov += 1
        return False

    unikatne_riadky.add(zaznam)
    return True


# ============================================================
# SPRACOVANIE ZDROJOV
# ============================================================

for nazov_zdroja, url in zdroje.items():

    print(f"Sťahujem {nazov_zdroja}...")

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=60
        )

        if response.status_code != 200:
            print(
                f"Chyba pri sťahovaní {nazov_zdroja}: "
                f"Status {response.status_code}"
            )
            continue

        pocet_z_tohto_zdroja = 0
        secrets_z_tohto_zdroja = 0


        # ====================================================
        # PHISHTANK
        # ====================================================

        if nazov_zdroja == "PhishTank":

            try:
                xml_data = bz2.decompress(response.content)
                root = ET.fromstring(xml_data)

                for entry in root.iter("entry"):

                    online_element = entry.find("status/online")

                    if (
                        online_element is None
                        or online_element.text != "yes"
                    ):
                        continue


                    url_element = entry.find("url")

                    if (
                        url_element is None
                        or not url_element.text
                    ):
                        continue


                    url_na_parsovanie = url_element.text.strip()

                    if (
                        not url_na_parsovanie
                        or url_na_parsovanie.startswith("#")
                    ):
                        continue


                    phish_detail_element = entry.find(
                        "phish_detail_url"
                    )

                    if (
                        phish_detail_element is not None
                        and phish_detail_element.text
                    ):
                        phish_detail_url = (
                            phish_detail_element.text.strip()
                        )
                    else:
                        phish_detail_url = ""


                    target_element = entry.find("target")

                    if (
                        target_element is not None
                        and target_element.text
                    ):
                        target = target_element.text.strip()
                    else:
                        target = "Unknown"


                    if "phish_id=" in phish_detail_url:
                        phish_id = phish_detail_url.split(
                            "phish_id="
                        )[-1]
                    else:
                        phish_id = "0000"


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


                        cista_domena = port_regex.sub(
                            "",
                            domena
                        )

                        cista_cesta = cesta


                        if not validna_domena_regex.fullmatch(
                            cista_domena
                        ):
                            continue


                        cisty_target = (
                            target
                            .replace(",", " ")
                            .replace(" ", "_")
                        )

                        komentar = (
                            f"{nazov_zdroja}_"
                            f"{cisty_target}_"
                            f"ID{phish_id}"
                        )


                        if pridaj_zaznam(
                            cista_domena,
                            cista_cesta,
                            komentar
                        ):
                            pocet_z_tohto_zdroja += 1
                        else:
                            secrets_z_tohto_zdroja += 1


                    except Exception:
                        continue


            except Exception as xml_err:

                print(
                    "Chyba pri dekompresii alebo parsovaní "
                    f"XML pre PhishTank: {xml_err}"
                )

                continue


        # ====================================================
        # URLHAUS + THREATFOX
        # ====================================================

        else:

            riadky_textu = response.text.splitlines()

            for riadok in riadky_textu:

                riadok = riadok.strip()


                if (
                    not riadok
                    or riadok.startswith(("#", ";"))
                ):
                    continue


                # --------------------------------------------
                # ThreatFox hostfile
                # --------------------------------------------

                if nazov_zdroja == "ThreatFox":

                    if riadok.startswith("127.0.0.1"):

                        casti = riadok.split()

                        if len(casti) > 1:
                            riadok = casti[1].strip()
                        else:
                            continue

                    else:
                        continue


                try:

                    url_na_parsovanie = riadok


                    if not url_na_parsovanie.startswith(
                        ("http://", "https://")
                    ):
                        url_na_parsovanie = (
                            "http://" + url_na_parsovanie
                        )


                    parsed_url = urlparse(
                        url_na_parsovanie
                    )


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


                    cista_domena = port_regex.sub(
                        "",
                        domena
                    )

                    cista_cesta = cesta


                    if not validna_domena_regex.fullmatch(
                        cista_domena
                    ):
                        continue


                    if pridaj_zaznam(
                        cista_domena,
                        cista_cesta,
                        nazov_zdroja
                    ):
                        pocet_z_tohto_zdroja += 1
                    else:
                        secrets_z_tohto_zdroja += 1


                except Exception:
                    continue


        print(
            f"-> Úspešne spracované zo "
            f"{nazov_zdroja}: "
            f"{pocet_z_tohto_zdroja} riadkov"
        )

        if secrets_z_tohto_zdroja > 0:
            print(
                f"-> Preskočené kvôli možným secretom: "
                f"{secrets_z_tohto_zdroja}"
            )


    except Exception as e:

        print(
            f"Zlyhalo spojenie so "
            f"{nazov_zdroja}: {e}"
        )


# ============================================================
# FINÁLNY ZÁPIS
# ============================================================

if len(unikatne_riadky) > 100:

    os.makedirs(
        "Lists",
        exist_ok=True
    )

    cesta_k_suboru = os.path.join(
        "Lists",
        "urlhaus_urls.txt"
    )


    with open(
        cesta_k_suboru,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(
                sorted(unikatne_riadky)
            )
        )


    print()
    print("========================================")
    print("HOTOVO")
    print("========================================")

    print(
        f"Súbor: {cesta_k_suboru}"
    )

    print(
        f"Unikátnych záznamov: "
        f"{len(unikatne_riadky)}"
    )

    print(
        f"Záznamov odstránených kvôli "
        f"možným secretom: "
        f"{pocet_odstranenych_secretov}"
    )


else:

    print(
        f"\nCHYBA: Málo záznamov "
        f"({len(unikatne_riadky)}). "
        f"Súbor nebol prepísaný."
    )

    raise SystemExit(1)
