-- Shared read-only data access for the panel and its future API adapters.
-- Generated records retain unknown values as absent; they are not zero-cost rules.
ASC.Data = ASC.Data or {}
local Data = ASC.Data
Data.Datasets = Data.Datasets or {}
local loading
local function positiveInteger(value)
    return type(value) == "number" and value > 0 and value == math.floor(value)
end
local function selected(key)
    local dataset = Data.Datasets[key or Data.ActiveKey]
    assert(dataset and dataset.complete, "Select a complete recovered dataset first")
    return dataset
end
function Data.BeginDataset(metadata)
    assert(not loading, "previous dataset is not finalized")
    assert(type(metadata) == "table" and metadata.format == 1 and type(metadata.key) == "string", "unsupported dataset metadata")
    assert(not Data.Datasets[metadata.key], "dataset already loaded: " .. metadata.key)
    loading = {metadata=metadata, entries={}, ordered={}, byClass={}, bySpell={}, unresolved={}}
end
function Data.SetTables(tables)
    assert(loading and not loading.tables, "tables must load once within a dataset")
    assert(type(tables) == "table" and type(tables.essence) == "table", "missing essence table")
    loading.tables = tables
end
function Data.AddEntry(entry)
    assert(loading, "BeginDataset must precede entries")
    assert(type(entry) == "table" and positiveInteger(entry.ID), "invalid entry ID")
    assert(not loading.entries[entry.ID], "duplicate entry ID")
    assert(type(entry.Class) == "string" and type(entry.Tab) == "string" and type(entry.Spells) == "table", "invalid entry shape")
    for _, spell in ipairs(entry.Spells) do assert(positiveInteger(spell), "invalid rank spell") end
    loading.entries[entry.ID] = entry
    loading.ordered[#loading.ordered+1] = entry.ID
end
function Data.FinalizeDataset()
    local d = assert(loading, "no dataset to finalize")
    assert(d.tables, "dataset tables were not loaded")
    assert(#d.ordered == d.metadata.entryCount, "entry count differs from generation manifest")
    table.sort(d.ordered)
    local relations = {"ConnectedNodes", "RequiredIDs", "Masteries"}
    for _, id in ipairs(d.ordered) do
        local e = d.entries[id]
        local class = d.byClass[e.Class]
        if not class then class={}; d.byClass[e.Class]=class end
        local bucket = class[e.Tab]
        if not bucket then bucket={}; class[e.Tab]=bucket end
        bucket[#bucket+1] = id
        local seen = {}
        for _, spell in ipairs(e.Spells) do
            if not seen[spell] then
                local ids = d.bySpell[spell]
                if not ids then ids={}; d.bySpell[spell]=ids end
                ids[#ids+1]=id; seen[spell]=true
            end
        end
        for _, kind in ipairs(relations) do
            for _, target in ipairs(e[kind] or {}) do
                if not d.entries[target] then
                    d.unresolved[#d.unresolved+1]={entry=id,kind=kind,target=target}
                end
            end
        end
    end
    local buckets = 0
    for _, tabs in pairs(d.byClass) do for _ in pairs(tabs) do buckets=buckets+1 end end
    assert(buckets == d.metadata.bucketCount, "bucket count differs from generation manifest")
    for _, expected in ipairs(d.metadata.buckets) do
        local ids = d.byClass[expected.Class] and d.byClass[expected.Class][expected.Tab]
        assert(ids and #ids == expected.Count, "class/tab count differs from generation manifest")
    end
    d.essence = {}
    for _, row in ipairs(d.tables.essence) do
        if row.Match1 == 0 and row.Match2 == 0 and row.Match3 == 0 and row.Match4 == 0 then
            local curve = d.essence[row.Family]
            if not curve then curve={}; d.essence[row.Family]=curve end
            assert(not curve[row.Level], "duplicate unconditional essence level")
            curve[row.Level]={row.AE,row.TE}
        end
    end
    d.complete=true
    Data.Datasets[d.metadata.key]=d
    loading=nil
    return d.metadata.key
end
function Data.SelectDataset(key)
    local d = selected(key)
    Data.ActiveKey=key
    return d.metadata
end
function Data.GetEntry(id, key)
    return selected(key).entries[id]
end
function Data.GetEntries(class, tab, key)
    local d=selected(key)
    local result={}
    for _, id in ipairs(d.ordered) do
        local entry=d.entries[id]
        if (not class or entry.Class == class) and (not tab or entry.Tab == tab) then result[#result+1]=entry end
    end
    return result
end
function Data.GetEntriesForSpell(spell, key)
    local d=selected(key)
    local result={}
    for _, id in ipairs(d.bySpell[spell] or {}) do result[#result+1]=d.entries[id] end
    return result
end
function Data.GetBudget(family, level, key)
    local curve=selected(key).essence[family]
    if not curve then return nil,nil,"unavailable" end
    local lo,hi
    for n in pairs(curve) do lo=lo and math.min(lo,n) or n; hi=hi and math.max(hi,n) or n end
    if type(level) ~= "number" then return nil,nil,"invalid-level" end
    local row=curve[math.max(lo,math.min(hi,level))]
    if not row then return nil,nil,"unavailable" end
    if row[1] == 0 and row[2] == 0 then return nil,nil,"withheld" end
    return row[1],row[2]
end
function Data.CanEvaluateLearn(id, key)
    local d=selected(key)
    local e=d.entries[id]
    if not e then return false,"unknown-entry" end
    if not e.Harvested then return false,"rules-not-harvested" end
    for _, field in ipairs({"RequiredLevel","AECost","TECost"}) do
        if type(e[field]) ~= "number" then return false,"missing-" .. field end
    end
    for _, value in ipairs(e.SpellCastReq or {}) do
        if value == "<table>" then return false,"opaque-spell-requirements" end
    end
    for _, kind in ipairs({"ConnectedNodes","RequiredIDs","Masteries"}) do
        for _, target in ipairs(e[kind] or {}) do
            if not d.entries[target] then return false,"missing-relationship" end
        end
    end
    -- Data completeness is necessary, never sufficient for server-authorized learning.
    return true
end
function Data.SelfTest(key)
    local d=selected(key)
    local blocked=0
    for _, id in ipairs(d.ordered) do
        if not Data.CanEvaluateLearn(id,key) then blocked=blocked+1 end
    end
    return {entries=#d.ordered,buckets=d.metadata.bucketCount,unresolvedRelationships=#d.unresolved,incompleteRuleEntries=blocked,dataset=d.metadata.key}
end
