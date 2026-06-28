import os
import re
import csv
import bz2
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import requests

# Definovanie zdrojov
zdroje = {
    "URLhaus": "https://urlhaus.abuse.ch/downloads/text/",
    "ThreatFox": "https://threatfox.abuse.ch/downloads/hostfile/",
    "PhishTank": "http://data.phishtank.com/data/online-valid.xml.bz2"
}

unikatne_riadky = set()
port_regex = re.compile(r":\d{1,5}")
# Regex pre overenie, že doména obsahuje iba bezpečné znaky a nie skomolené binárne dáta
validna_domena_regex = re.compile(r"^[a-zA-Z0-9.-]+$")
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

for nazov_zdroja, url in zdroje.items():
    print(f"Sťahujem {nazov_zdroja}...")
    try:
        response = requests.get(url, headers=headers, timeout=45)
        if response.status_code != 200:
            print(f"Chyba pri sťahovaní {nazov_zdroja}: Status {response.status_code}")
            continue

        pocet_z_tohto_zdroja = 0

        # === ŠPECIFICKÉ PARSOVANIE PRE PHISHTANK (XML v BZ2) ===
        if nazov_zdroja == "PhishTank":
            try:
                # Dekompresia BZ2 dát priamo v pamäti
                xml_data = bz2.decompress(response.content)
                root = ET.fromstring(xml_data)
                
                # Prechádzame jednotlivé <entry> záznamy
                for entry in root.iter('entry'):
                    # 1. Kontrola, či je záznam aktuálne ONLINE
                    online_element = entry.find('status/online')
                    if online_element is None or online_element.text != 'yes':
                        continue
                    
                    # 2. Vytiahnutie a vyčistenie URL
                    url_element = entry.find('url')
                    if url_element is None or not url_element.text:
                        continue
                        
                    url_na_parsovanie = url_element.text.strip()
                    if not url_na_parsovanie or url_na_parsovanie.startswith("#"):
                        continue
                    
                    # 3. Vytiahnutie detailov pre Flowmon-friendly komentár
                    phish_detail_url = entry.find('phish_detail_url')
                    phish_detail_url = phish_detail_url.text.strip() if (phish_detail_url is not None and phish_detail_url.text) else ""
                    
                    target = entry.find('target')
                    target = target.text.strip() if (target is not None and target.text) else "Unknown"

                    # Vytiahnutie ID z URL (napr. z http://..._id=9464515 vytiahne len 9464515)
                    phish_id = phish_detail_url.split("phish_id=")[-1] if "phish_id=" in phish_detail_url else "0000"

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
                        
                        čista_domena = port_regex.sub("", domena)
                        čista_cesta = port_regex.sub("", cesta)
                        
                        # Bezpečnostný filter na neplatné znaky v doméne
                        if not validna_domena_regex.match(čista_domena):
                            continue
                        
                        # Príprava kompaktného komentára bez nebezpečných znakov (čiarky, zátvorky, medzery)
                        čisty_target = target.replace(",", " ").replace(" ", "_")
                        komentar = f"{nazov_zdroja}_{čisty_target}_ID{phish_id}"
                        
                        unikatne_riadky.add(f"{čista_domena},{čista_cesta},{komentar}")
                        pocet_z_tohto_zdroja += 1
                    except:
                        continue
            except Exception as xml_err:
                print(f"Chyba pri dekompresii alebo parsovaní XML pre PhishTank: {xml_err}")
                continue

        # === PARSOVANIE PRE OSTATNÉ TXT ZDROJE (URLhaus, ThreatFox) ===
        else:
            riadky_textu = response.text.splitlines()
            for riadok in riadky_textu:
                riadok = riadok.strip()
                if not riadok or riadok.startswith(("#", ";")):
                    continue
                
                # Ošetrenie špecifického formátu ThreatFoxu (127.0.0.1 [tab] domena)
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
                        
                    čista_domena = port_regex.sub("", domena)
                    čista_cesta = port_regex.sub("", cesta)
                    
                    # Bezpečnostný filter na neplatné znaky v doméne
                    if not validna_domena_regex.match(čista_domena):
                        continue
                        
                    unikatne_riadky.add(f"{čista_domena},{čista_cesta},{nazov_zdroja}")
                    pocet_z_tohto_zdroja += 1
                except:
                    continue

        print(f"-> Úspešne spracované zo {nazov_zdroja}: {pocet_z_tohto_zdroja} riadkov")

    except Exception as e:
        print(f"Zlyhalo spojenie so {nazov_zdroja}: {e}")

# Finálny zápis do súboru (iba ak máme dostatok dát)
if len(unikatne_riadky) > 100:
    with open("urlhaus_urls.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(unikatne_riadky)))
    print(f"\nHOTOVO. Spojený súbor obsahuje celkovo {len(unikatne_riadky)} unikátnych záznamov.")
else:
    print("\nCHYBA: Málo záznamov. Súbor nebol prepísaný.")
    exit(1)
