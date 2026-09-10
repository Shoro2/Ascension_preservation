-- Ascension stock-client compatibility foundation. Lua 5.1.
ASC = ASC or {}
ASC.Version = "0.1.0-dev"
ASC.Protocol = 1
function ASC.Namespace(name)
    assert(type(name) == "string" and name:match("^C_[%w_]+$"), "invalid namespace")
    if _G[name] == nil then _G[name] = {} end
    assert(type(_G[name]) == "table", name .. " already exists and is not a table")
    return _G[name]
end
-- Implemented API modules opt in here; do not pre-create pure-Lua namespaces
-- whose own source uses `if not C_Name then ...` initialization guards.
