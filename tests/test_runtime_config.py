import os, subprocess, sys, json, tempfile, unittest
from pathlib import Path
SERVER = Path(__file__).resolve().parents[1] / 'server'

class RuntimeConfigurationTests(unittest.TestCase):
    def test_existing_state_and_relative_asset_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();state=root/'existing-state';state.mkdir()
            sentinel=state/'characters.json';sentinel.write_text('{}')
            config=root/'runtime.local.json'
            config.write_text(json.dumps({'runtime_dir':'new-runtime','state_dir':'existing-state','dbc_dir':'assets/dbc','ca_ref_dir':'assets/ca'}))
            env=dict(os.environ,ASC_CONFIG=str(config),PYTHONPATH=str(SERVER))
            for key in ('ASC_RUNTIME_DIR','ASC_DATA_DIR','ASC_LOG_DIR','ASC_DBC_DIR','ASC_CA_REF'):env.pop(key,None)
            code="import json,world_server as w,runtime_paths as p; print(json.dumps({'state':w.DATA_DIR,'dbc':w.DBC_DIR,'ca':w.CA_REF_DIR,'logs':p.LOGS}))"
            r=subprocess.run([sys.executable,'-B','-c',code],env=env,capture_output=True,text=True,check=True)
            actual=json.loads(r.stdout.strip().splitlines()[-1])
            self.assertEqual(Path(actual['state']),state)
            self.assertEqual(Path(actual['dbc']),root/'assets/dbc')
            self.assertEqual(Path(actual['ca']),root/'assets/ca')
            self.assertEqual(sentinel.read_text(),'{}')
            self.assertNotIn(SERVER,Path(actual['logs']).parents)
    def test_environment_override_wins(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();config=root/'runtime.local.json';config.write_text(json.dumps({'state_dir':'old'}))
            env=dict(os.environ,ASC_CONFIG=str(config),ASC_DATA_DIR=str(root/'chosen'),PYTHONPATH=str(SERVER))
            r=subprocess.run([sys.executable,'-B','-c','import runtime_paths; print(runtime_paths.STATE)'],env=env,capture_output=True,text=True,check=True)
            self.assertEqual(Path(r.stdout.strip()),root/'chosen')

if __name__=='__main__':unittest.main()
