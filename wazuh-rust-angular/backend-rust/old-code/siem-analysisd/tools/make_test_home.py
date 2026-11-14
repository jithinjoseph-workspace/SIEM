#!/usr/bin/env python3
"""Build a Wazuh-home-like directory and the list of ruleset unit tests the
way ruleset/testing/runtests.py does, so that the Rust engine can be checked
against Wazuh's own expectations.

usage: make_test_home.py <wazuh-src> <out-home> <out-cases.json> [--geoip]

* ruleset/{decoders,rules} and etc/lists are copied from the source tree,
  etc/{decoders,rules} get local_decoder.xml / local_rules.xml plus the
  test_*decoders.xml / test_*rules.xml of ruleset/testing/ruleset
  (provisionDR).
* rule 60000 of 0575-win-base_rules.xml is rewritten with ElementTree exactly
  like enable_win_eventlog_test_actions() (including ElementTree's
  re-serialisation of the file).
* tests/*.ini are parsed with the same RawConfigParser/MultiOrderedDict
  setup; every "log ..." value becomes one test case. Each case is one
  wazuh-logtest run: the value is split in lines (input() per line, empty
  lines skipped), all lines go to the same session, and the unit-test result
  of the last processed line is compared.
"""

import configparser
import json
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict


class MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super(MultiOrderedDict, self).__setitem__(key, value)


def enable_win_eventlog_test_actions(tree):
    base_rule = tree.find('.//rule[@id="60000"]')
    decoded_as_elem = base_rule.find(".//decoded_as")
    if decoded_as_elem is not None:
        base_rule.remove(decoded_as_elem)
    category_elem = base_rule.find(".//category")
    if category_elem is not None:
        base_rule.remove(category_elem)
    decoded_as = ET.SubElement(base_rule, "decoded_as")
    decoded_as.text = "json"


def main():
    src, home, cases_out = sys.argv[1], sys.argv[2], sys.argv[3]
    geoip = "--geoip" in sys.argv[4:]

    if os.path.exists(home):
        shutil.rmtree(home)
    for d in ("ruleset", "etc/decoders", "etc/rules", "queue/diff", "queue/fts"):
        os.makedirs(os.path.join(home, d), exist_ok=True)

    shutil.copytree(os.path.join(src, "ruleset", "decoders"), os.path.join(home, "ruleset", "decoders"))
    shutil.copytree(os.path.join(src, "ruleset", "rules"), os.path.join(home, "ruleset", "rules"))
    shutil.copytree(os.path.join(src, "ruleset", "lists"), os.path.join(home, "etc", "lists"))
    shutil.copy2(os.path.join(src, "etc", "local_decoder.xml"), os.path.join(home, "etc", "decoders", "local_decoder.xml"))
    shutil.copy2(os.path.join(src, "etc", "local_rules.xml"), os.path.join(home, "etc", "rules", "local_rules.xml"))
    shutil.copy2(os.path.join(src, "etc", "ossec-server.conf"), os.path.join(home, "ossec.conf"))
    shutil.copy2(os.path.join(src, "etc", "ossec-server.conf"), os.path.join(home, "etc", "ossec.conf"))
    shutil.copy2(os.path.join(src, "etc", "internal_options.conf"), os.path.join(home, "etc", "internal_options.conf"))

    tdir = os.path.join(src, "ruleset", "testing", "ruleset")
    for f in os.listdir(tdir):
        full = os.path.join(tdir, f)
        if os.path.isfile(full) and re.match(r'^test_(.*_)?rules.xml$', f):
            shutil.copy2(full, os.path.join(home, "etc", "rules"))
        if os.path.isfile(full) and re.match(r'^test_(.*_)?decoders.xml$', f):
            shutil.copy2(full, os.path.join(home, "etc", "decoders"))

    win = os.path.join(home, "ruleset", "rules", "0575-win-base_rules.xml")
    tree = ET.parse(win)
    enable_win_eventlog_test_actions(tree)
    tree.write(win)

    cases = []
    tests = os.path.join(src, "ruleset", "testing", "tests")
    for ini in sorted(os.listdir(tests)):
        if not ini.endswith(".ini"):
            continue
        if not geoip and ini.endswith("geoip.ini"):
            continue
        tg = configparser.RawConfigParser(dict_type=MultiOrderedDict, strict=False)
        tg.read([os.path.join(tests, ini)], encoding="utf-8")
        for sec in tg.sections():
            rule = tg.get(sec, "rule")
            alert = tg.get(sec, "alert")
            decoder = tg.get(sec, "decoder")
            for (name, value) in tg.items(sec):
                if name.startswith("log "):
                    neg = name.endswith("fail")
                    # universal_newlines + input(): one event per line
                    lines = [l for l in value.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
                    cases.append({
                        "file": ini, "section": sec, "name": name, "events": lines,
                        "rule": rule, "alert": alert, "decoder": decoder, "negate": neg,
                    })
    with open(cases_out, "w", encoding="utf-8") as f:
        json.dump(cases, f, ensure_ascii=False)
    print("%d cases" % len(cases))


if __name__ == "__main__":
    main()
