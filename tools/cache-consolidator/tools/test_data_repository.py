import contextlib, io, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import publish

class DataRepositoryTests(unittest.TestCase):
    def test_marker_prevents_source_sync(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,".ascension-data.json").write_text("{}",encoding="utf8")
            with patch.object(publish,"REPO",d),patch.object(publish,"nul") as git:
                self.assertEqual(publish.sync_tools(),[])
                git.assert_not_called()
    def test_help_never_publishes(self):
        with patch.object(publish,"publish") as run,contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:publish.main(["--help"])
            self.assertEqual(result.exception.code,0)
            run.assert_not_called()
if __name__=="__main__": unittest.main()
