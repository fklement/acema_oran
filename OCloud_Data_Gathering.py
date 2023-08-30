import csv
import json
import os
import shutil
import time
from datetime import date

import cve_lookup
import mitreattack.attackToExcel.attackToExcel as attackToExcel
import mitreattack.attackToExcel.stixToDf as stixToDf
import nvdlib
import pandas as pd
from cwe2.database import Database
from git import InvalidGitRepositoryError, Repo
from stix2 import Filter


class cve_custom_encoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__


db = Database()
filt = Filter('type', '=', 'attack-pattern')
fs = None


def get_formatted_runtime(start, end):
    hours, rem = divmod(end - start, 3600)
    minutes, seconds = divmod(rem, 60)
    return "{:0>2}h {:0>2}m and {:05.2f}s".format(int(hours), int(minutes), seconds)


def get_attack_pattern_by_capec_id(src, capec_id):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', 'CAPEC-' + capec_id),
        Filter('external_references.source_name', '=', 'capec'),
    ]
    return src.query(filt)


def get_capec_external_references_cwes(src, capec):
    id = capec.split("-")[1]
    test = get_attack_pattern_by_capec_id(src, id)
    if len(test) != 0:
        return test[0]["external_references"]
    else:
        return []


def iterate_cve_for_given_cwe(db, cwe):
    cve_list = []
    weakness = db.get(cwe.split("-")[1])
    observed_examples = weakness.__dict__["observed_examples"]
    cves = [word for word in observed_examples.split(":") if word.startswith("CVE-")]

    for cve in cves:
        cve_full = None
        while cve_full is None:
            try:
                cve_full = cve_lookup.cve(cve)
                print(f"{cve_full.id}, ", end='')
            except Exception as e:
                print(f"\nError during lookup for cve entry ..\n -> {e} \n Retrying.\n")
                time.sleep(3)

        r = None
        while r is None:
            try:
                r = nvdlib.searchCVE(cveId=cve, key='8051e78c-9d20-4b6d-9bcb-20ce09eed8b8')[0]

                cve_list.append({"id": cve_full.id,
                                 "score": r.score,
                                 "v2_score": r.v2score,
                                 "v2_exploitability_score": r.v2exploitability,
                                 "v2_impact_score": r.v2impactScore,
                                 "v2_vector": r.v2vector,
                                 "access_vector": r.metrics.cvssMetricV2[0].cvssData.accessVector,
                                 "full_metrics": r.metrics.cvssMetricV2,
                                 "description": r.descriptions[0].value,
                                 "cpe_vulnerable": r.cpe[0].vulnerable,
                                 "cpe_criteria": r.cpe[0].criteria,
                                 "published": r.published,
                                 "last_modified": r.lastModified
                                 })

            except Exception as e:
                print(f"\nError during fetch for {cve_full.id}..\n -> {e} \n Retrying.\n")
                time.sleep(10)

    return {"cwe": cwe, "cves": cve_list, "cwe_info": weakness.__dict__}


def pull_clone_gitrepo(directory, repo):
    # Check if the data direcory exists
    if not os.path.isdir(directory):
        Repo.clone_from(repo, directory)
    else:
        try:
            # Check if the data directory is actually a repositry then pull the canges
            repo = Repo(directory)
            repo.remotes.origin.pull()
        except InvalidGitRepositoryError:
            # If not then remove the folder
            shutil.rmtree(directory)
            Repo.clone_from(repo, directory)


def generate_techniques_dataframe():
    # download and parse ATT&CK STIX data
    attackdata = attackToExcel.get_stix_data("enterprise-attack", "v4.0")
    # get Pandas DataFrames for techniques, associated relationships, and citations
    techniques_data = stixToDf.techniquesToDf(attackdata, "enterprise-attack")
    return techniques_data["techniques"]


def get_grouped_o_cloud_technique(file, drop_duplicates: bool = False):
    # Extract CAPEC's for our selected O-Cloud threats and return them.
    o_cloud = pd.read_csv(file, sep=';', index_col=0)
    if drop_duplicates:
        o_cloud = o_cloud.drop_duplicates(subset=["Technique"])
    return o_cloud.groupby("Name")


def get_technique_capecs_id(grouped, techniques_df):
    techniques_capecs = []
    for s, group in grouped:
        for i in group["Technique"].drop_duplicates():
            capecs = []
            for capec in techniques_df[techniques_df["ID"].str.contains(i)]["CAPEC ID"]:
                try:
                    float(capec)
                except:
                    for c in capec.split(", "):
                        capecs.append(c)
            techniques_capecs.append((i, capecs))
    return techniques_capecs


def write_ids_to_file(techniques_capecs, file):
    f = open(file, 'w')
    writer = csv.writer(f)
    writer.writerow(['Technique ID', 'CAPEC ID'])

    for t_name, capec_ids in techniques_capecs:
        if len(capec_ids) != 0:
            for id in capec_ids:
                writer.writerow([t_name, id])
    f.close()


def print_stats(techniques_capecs):
    count_capecs = 0
    count_techniques = 0
    count_empty_techniques = 0
    for (t, l_capec) in techniques_capecs:
        len_l = len(l_capec)
        count_techniques += 1
        count_capecs += len_l
        if len_l == 0:
            count_empty_techniques += 1

    print(f"Techniques: {count_techniques}")
    print(f"Empty Techniques: {count_empty_techniques}")
    print(f"CAPECs: {count_capecs}")


def find_cwe_for_capec(techniques_capecs, fs):
    capec_list = []
    list_of_tinfos = []
    start = time.time()
    print("Start fetching CAPEC'S -> CWE'S -> CVE'S for given CAPEC-IDS...")
    for t_id, capec_ids in techniques_capecs:
        if len(capec_ids) != 0:
            capec_list = []
            for c_id in capec_ids:
                print(f"\nSearching CVE's for {c_id}")
                print("Found: ", end='')
                findings = []
                for reference in get_capec_external_references_cwes(fs, c_id):
                    if reference["source_name"] == "cwe":
                        findings.append(iterate_cve_for_given_cwe(db, reference["external_id"]))
                capec_list.append({"capec_id": c_id, "c_findings": findings})
                print("\n")
        list_of_tinfos.append({"technique_id": t_id, "t_findings": capec_list})
    end = time.time()
    print(f"Finished in {get_formatted_runtime(start, end)}.")
    return {
        "scan_date": f"{date.today()}",
        "scan_runtime": get_formatted_runtime(start, end),
        "data": list_of_tinfos
    }


def write_dict_to_file(t_cwe_cve_dict, file):
    with open(file, "w") as outfile:
        json.dump(t_cwe_cve_dict, outfile, cls=cve_custom_encoder)
