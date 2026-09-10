"""Keep one copy of each guide, and keep its links and commands real.

The four cache guides existed twice for a while -- once here, once in the data
repository -- and within a day they had drifted: one copy grew a section the
other never got, three grew a banner this one never got. Nothing synced them and
nothing complained, so the next reader would have silently picked a side.

The fix was structural: the copy beside the tools is the only copy, and the data
repository keeps the same four paths as short signposts to it. This test is what
makes that hold. It asserts the canonical guide exists, that no second full copy
has reappeared anywhere in this repository, that every relative link in the
component's markdown resolves, and that every tool command the docs tell a reader
to type names a script that is actually here -- because a guide whose commands
have quietly gone stale is worse than no guide, and the person it strands is the
one who does not write code.

The last check reaches into a data-repository checkout when one is configured and
verifies those four paths are still signposts rather than copies. It skips when
there is no checkout, so CI runs the rest.

    python test_docs.py
"""
import os, re, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
COMPONENT = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(COMPONENT))
DOCS = os.path.join(COMPONENT, "docs")

CANONICAL = ["USING-THE-DATA.md", "VERIFYING-THE-DATA.md", "WDB-FORMAT.md",
             "GAMEOBJECT-DUMPS.md"]
CANONICAL_URL = ("https://github.com/hertigservices/Ascension_preservation/"
                 "blob/main/tools/cache-consolidator/docs/")

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
COMMAND = re.compile(r"python(?:\s+-B)?\s+tools/([A-Za-z0-9_]+\.py)")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def markdown(root):
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for name in sorted(names):
            if name.lower().endswith(".md"):
                yield os.path.join(base, name)


def data_repository():
    """A configured data-repository checkout, or None.

    Read the same two places config.py reads, without importing it: this test
    must stay runnable in a checkout that has no runtime file at all.
    """
    found = os.environ.get("CONSOLIDATOR_REPO")
    if not found:
        runtime = os.path.join(HERE, "runtime.local.json")
        if os.path.exists(runtime):
            import json
            with open(runtime, encoding="utf-8-sig") as f:
                found = json.load(f).get("publish_repo")
    if found and os.path.isdir(os.path.join(found, "docs")):
        return found
    return None


class DocumentationTests(unittest.TestCase):
    def test_canonical_guides_are_here_and_whole(self):
        for name in CANONICAL:
            path = os.path.join(DOCS, name)
            self.assertTrue(os.path.exists(path), "%s is missing" % path)
            # A signpost is about 700 bytes; the real guides are thousands. This
            # separates "the guide is here" from "the guide became a stub here
            # and moved somewhere unnamed".
            self.assertGreater(len(read(path)), 3000, "%s looks like a stub" % name)

    def test_no_second_copy_anywhere_in_this_repository(self):
        for name in CANONICAL:
            copies = [p for p in markdown(REPO)
                      if os.path.basename(p) == name]
            self.assertEqual(len(copies), 1,
                             "%s exists %d times: %s" % (name, len(copies), copies))

    def test_every_relative_link_resolves(self):
        broken = []
        for path in markdown(COMPONENT):
            for target in LINK.findall(read(path)):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                target = target.split("#")[0]
                if not target:
                    continue
                if not os.path.exists(os.path.join(os.path.dirname(path), target)):
                    broken.append("%s -> %s" % (os.path.relpath(path, COMPONENT), target))
        self.assertEqual(broken, [])

    def test_every_command_the_docs_give_names_a_real_script(self):
        missing = []
        for path in markdown(COMPONENT):
            for script in sorted(set(COMMAND.findall(read(path)))):
                if not os.path.exists(os.path.join(COMPONENT, "tools", script)):
                    missing.append("%s -> tools/%s" % (os.path.relpath(path, COMPONENT), script))
        self.assertEqual(missing, [])

    def test_data_repository_keeps_signposts_not_copies(self):
        repo = data_repository()
        if not repo:
            self.skipTest("no data-repository checkout configured")
        for name in CANONICAL:
            path = os.path.join(repo, "docs", name)
            if not os.path.exists(path):
                continue
            text = read(path)
            self.assertLess(len(text), 4000,
                            "%s has grown back into a second copy" % path)
            self.assertIn(CANONICAL_URL + name, text,
                          "%s does not point at the canonical guide" % path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
