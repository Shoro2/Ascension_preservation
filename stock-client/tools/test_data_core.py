#!/usr/bin/env python3
"""Offline Lua 5.1 and source/output consistency checks; never opens a client or DB."""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import unittest
from lupa.lua51 import LuaRuntime
import gen_ca_data as gen

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'client/Interface/AddOns/!AscensionShim/core'


def assert_lua_value(expected, actual, label):
    if isinstance(expected, dict):
        assert actual is not None and set(actual.keys()) == set(expected), label
        for key, value in expected.items(): assert_lua_value(value, actual[key], label + '.' + str(key))
    elif isinstance(expected, list):
        assert actual is not None and set(actual.keys()) == set(range(1,len(expected)+1)), label
        for key, value in enumerate(expected,1): assert_lua_value(value,actual[key],label+'['+str(key)+']')
    else:
        assert actual == expected and (isinstance(expected,bool) == isinstance(actual,bool)), (label,expected,actual)


def runtime():
    rt=LuaRuntime(unpack_returned_tuples=True)
    for name in ('Namespaces.lua','Data.lua','EventBus.lua','CustomEvents.lua'):
        rt.execute((CORE/name).read_text(encoding='utf-8-sig'))
    assert rt.eval('_VERSION') == 'Lua 5.1'
    return rt


class GeneratorTests(unittest.TestCase):
    def row(self):
        return {'realm':'test','mode':'coa','node':'1','ID':'1','Name':'Example','Class':'Tinker','Tab':'Firearms','Spells':'[{"id":42,"name":"rank one"},{"id":43,"name":"rank two"}]','ConnectedNodes':'[]','isTalent':'False','RequiredLevel':'10','AECost':'2','TECost':'0'}
    def harvest(self, rows):
        buffer=io.StringIO(newline=''); writer=csv.DictWriter(buffer,fieldnames=list(rows[0]),delimiter='\t')
        writer.writeheader();writer.writerows(rows)
        return buffer.getvalue().encode()
    def test_spell_rank_order_and_boolean(self):
        row=gen.normalize(self.row())
        self.assertEqual(row['Spells'],[42,43]);self.assertIs(row['isTalent'],False)
        self.assertEqual(row['SpellNames']['43'],'rank two')
    def test_modes_do_not_merge(self):
        a=self.row(); b=dict(a,mode='freepick',AECost='0')
        groups=gen.load_harvest(self.harvest([a,b]))
        self.assertEqual(len(groups),2)
        self.assertEqual({g['entries'][1]['AECost'] for g in groups.values()},{0,2})
    def test_conflicting_duplicate_refused(self):
        a=self.row();b=dict(a,AECost='0')
        with self.assertRaisesRegex(ValueError,'conflicting duplicate'):gen.load_harvest(self.harvest([a,b]))
    def test_missing_values_are_not_zero(self):
        row=gen.normalize(dict(self.row(),AECost=''))
        self.assertNotIn('AECost',row)
    def test_malformed_spell_cell_refused(self):
        for value in ('not json','{}','[true]','[{"id":0}]'):
            with self.assertRaises((ValueError,KeyError)):gen.normalize(dict(self.row(),Spells=value))
    def test_lua_escaping_roundtrips(self):
        rt=runtime(); value={'quote':'"\\\n\r\t\x00123','unicode':'é漢字','false':False,'array':[1,2,3]}
        assert_lua_value(value,rt.eval(gen.lua(value)),'fixture')
    def test_dbc_bounds(self):
        with self.assertRaises(ValueError):gen.dbc_rows(b'WDBC'+b'\0'*16+b'bad')
    def test_event_routing(self):
        rt=runtime()
        rt.execute('''
        local methods={}
        function methods:RegisterEvent(name) self.stock[name]=true; return "native" end
        function methods:UnregisterEvent(name) self.stock[name]=nil end
        function methods:UnregisterAllEvents() self.stock={} end
        function methods:IsEventRegistered(name) return self.stock[name] == true end
        function methods:GetScript(name) return self.scripts[name] end
        local mt={__index=methods}
        local frame=setmetatable({stock={},scripts={}},mt)
        local other=setmetatable({stock={},scripts={}},mt)
        ASC.Events.InstallFrameType(frame)
        ASC.Events.InstallFrameType(other) -- must not double-wrap shared methods
        ASC.Events.Define({"ASC_TEST"})
        assert(frame:RegisterEvent("PLAYER_LOGIN") == "native")
        assert(frame:IsEventRegistered("PLAYER_LOGIN"))
        frame:RegisterEvent("ASC_TEST");frame:RegisterEvent("ASC_TEST")
        assert(not frame.stock.ASC_TEST and frame:IsEventRegistered("ASC_TEST"))
        local count=0
        frame.scripts.OnEvent=function(self,event,a,b,c)
            assert(event=="ASC_TEST" and a==1 and b==nil and c==3)
            count=count+1;self:UnregisterEvent(event)
        end
        ASC.Events.Fire("ASC_TEST",1,nil,3);ASC.Events.Fire("ASC_TEST",1,nil,3)
        assert(count==1 and not frame:IsEventRegistered("ASC_TEST"))
        frame:RegisterEvent("ASC_TEST");frame:UnregisterAllEvents()
        assert(not frame:IsEventRegistered("ASC_TEST") and not frame:IsEventRegistered("PLAYER_LOGIN"))
        local errors=0
        geterrorhandler=function() return function() errors=errors+1 end end
        frame:RegisterEvent("ASC_TEST");other:RegisterEvent("ASC_TEST")
        frame.scripts.OnEvent=function() error("expected handler failure") end
        local received=false
        other.scripts.OnEvent=function() received=true end
        ASC.Events.Fire("ASC_TEST")
        assert(errors==1 and received)
        ''')


def verify_generated(data_root):
    manifest=json.loads((data_root/'generation.json').read_text(encoding='utf-8-sig'))
    for name,digest in manifest['outputs'].items():
        assert hashlib.sha256((data_root/name).read_bytes()).hexdigest()==digest, name
    results=[]
    for dataset in manifest['datasets']:
        base=data_root/'datasets'/dataset['key']
        expected=json.loads((base/'entries.json').read_text(encoding='utf-8-sig'))
        rt=runtime()
        for relative in (base/'load-order.txt').read_text(encoding='utf-8-sig').splitlines():
            raw=(base/relative).read_bytes()
            if relative.startswith('lua/entries/'):
                assert len(raw)<=gen.MAX_LUA_BYTES, relative
            rt.execute(raw.decode('utf-8-sig'))
        data=rt.globals().ASC.Data
        data.SelectDataset(dataset['key'])
        for record in expected:
            assert_lua_value(record,data.GetEntry(record['ID']),str(record['ID']))
        # Independently decode every ca_entry's SQL JSON, then compare with Lua/JSON source.
        sql_entries=[]
        with (base/'world-staging.sql').open(encoding='utf-8') as source:
            for line in source:
                if line.startswith('INSERT INTO ca_entry VALUES '):
                    match=re.search(r"CONVERT\(X'([0-9a-f]+)' USING utf8mb4\)\);$",line.strip())
                    assert match, line[:100]
                    sql_entries.append(json.loads(bytes.fromhex(match[1]).decode('utf-8')))
        assert sql_entries==expected, 'SQL and client entries differ'
        ae,te=data.GetBudget(28,80)
        assert (ae,te)==(36,35), 'Tinker must use family28'
        assert data.GetBudget(10,80)==(140,71), 'Free-Pick must use family10'
        assert data.GetBudget(99999,80)==(None,None,'unavailable')
        assert data.CanEvaluateLearn(1149)==(False,'rules-not-harvested')
        assert data.CanEvaluateLearn(30610)==(False,'missing-relationship')
        summary=data.SelfTest()
        gaps=json.loads((base/'gaps.json').read_text(encoding='utf-8-sig'))
        assert summary['unresolvedRelationships']==len(gaps['missing_relationships'])
        results.append({'dataset':dataset['key'],'entries':len(expected),'buckets':summary['buckets'],'unresolvedRelationships':summary['unresolvedRelationships'],'incompleteRuleEntries':summary['incompleteRuleEntries']})
    print(json.dumps({'lua':'5.1','datasetChecks':results},indent=2))
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data',type=Path,default=ROOT/'data')
    args=parser.parse_args()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(GeneratorTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():return 1
    verify_generated(args.data)
    return 0

if __name__=='__main__':raise SystemExit(main())
