-- Route explicitly inventoried Ascension events, preserving stock event methods.
ASC.Events = ASC.Events or {}
local Events=ASC.Events
local custom={}
local listeners={}
local installed=setmetatable({}, {__mode="k"})
local function weakKeys() return setmetatable({}, {__mode="k"}) end
function Events.Define(names)
    for _, name in ipairs(names) do
        assert(type(name) == "string" and name ~= "", "invalid custom event")
        custom[name]=true
    end
end
function Events.IsCustom(name) return custom[name] == true end
local function unregister(frame, event)
    if listeners[event] then listeners[event][frame]=nil end
end
function Events.InstallFrameType(frame)
    local mt=getmetatable(frame)
    local methods=mt and mt.__index
    assert(type(methods) == "table", "unsupported frame method table")
    if installed[methods] then return end
    local register=assert(methods.RegisterEvent,"missing native RegisterEvent")
    local remove=assert(methods.UnregisterEvent,"missing native UnregisterEvent")
    local removeAll=assert(methods.UnregisterAllEvents,"missing native UnregisterAllEvents")
    local isRegistered=methods.IsEventRegistered
    installed[methods]=true
    methods.RegisterEvent=function(self,event,...)
        if not custom[event] then return register(self,event,...) end
        if not listeners[event] then listeners[event]=weakKeys() end
        listeners[event][self]=true
    end
    methods.UnregisterEvent=function(self,event,...)
        if not custom[event] then return remove(self,event,...) end
        unregister(self,event)
    end
    methods.UnregisterAllEvents=function(self,...)
        for event in pairs(listeners) do unregister(self,event) end
        return removeAll(self,...)
    end
    if isRegistered then
        methods.IsEventRegistered=function(self,event,...)
            if custom[event] then return listeners[event] and listeners[event][self] == true or false end
            return isRegistered(self,event,...)
        end
    end
end
function Events.Fire(event,...)
    assert(custom[event], "custom event not inventoried: " .. tostring(event))
    local set=listeners[event]
    if not set then return end
    local frames={}
    for frame in pairs(set) do frames[#frames+1]=frame end
    local args={n=select("#",...),...}
    for _, frame in ipairs(frames) do
        if set[frame] then
            local handler=frame:GetScript("OnEvent")
            if handler then
                local function invoke() handler(frame,event,unpack(args,1,args.n)) end
                local report=geterrorhandler and geterrorhandler() or function(err) return err end
                xpcall(invoke,report)
            end
        end
    end
end
function Events.Install()
    -- XML-created frames use the same native per-type method tables as these probes.
    -- Keep the supported-type assumption under in-client verification before P2 acceptance.
    local types={"Frame","Button","CheckButton","EditBox","ScrollFrame","Slider","StatusBar","Cooldown","PlayerModel","DressUpModel","Model","SimpleHTML","GameTooltip","Minimap","MessageFrame","ScrollingMessageFrame","ColorSelect"}
    local failures={}
    for _, kind in ipairs(types) do
        local ok, frame=pcall(CreateFrame,kind)
        if ok and frame then
            frame:Hide()
            local installedOK,err=pcall(Events.InstallFrameType,frame)
            if not installedOK then failures[#failures+1]=kind .. ": " .. tostring(err) end
        else
            failures[#failures+1]=kind .. ": unavailable"
        end
    end
    return failures
end
