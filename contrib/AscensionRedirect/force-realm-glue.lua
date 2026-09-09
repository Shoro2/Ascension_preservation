--
-- Ascension realm redirect WITHOUT WinDivert, admin, or a kernel driver.
--
-- WHERE THIS GOES
--   <ClientRoot>\Interface\GlueXML\AccountLogin.lua
--
--   That path does not exist in a stock install -- the file lives inside
--   Data\patch-B.MPQ. The client prefers a LOOSE Interface file over the MPQ
--   copy, so:
--     1. extract AccountLogin.lua from patch-B.MPQ,
--     2. paste the block below near the top of it,
--     3. add the two call sites shown at the bottom,
--     4. drop it at Interface\GlueXML\AccountLogin.lua in the client root.
--   Deleting that one loose file restores stock behaviour exactly; the archive
--   itself is never modified.
--
-- WHY CONFIG.WTF IS NOT ENOUGH
--   Measured: write 127.0.0.1 into WTF\Config.wtf, and at the login screen glue
--   Lua reads the realmList CVar back as the portal address, before a key is
--   pressed. Something native restores it after the file is parsed. realmName
--   from Config.wtf *is* honoured (it labels the login screen), realmList is
--   not. So Config.wtf alone sends every login to the live service.
--
-- WHY THIS WORKS
--   Glue Lua is the last code that runs before ConnectToServer(), and this is
--   the same mechanism Ascension's own realm dropdown uses:
--   AccountLoginDropDown_OnClick calls SetCVar("realmList", ...) and lets the
--   engine dial it. Forcing the CVar in the same place is not a hack around the
--   client, it is the client's own path.
--
-- ONE TRAP
--   The client's NATIVE autologin (-login / -password, which the official
--   Electron launcher passes) does NOT go through glue Lua at all. It dials on
--   its own, before AccountLogin_OnShow, and ignores the CVar. Launch with NO
--   autologin arguments and type the credentials at the login screen.
--
-- Include the port. A bare "127.0.0.1" dials the WoW-default 3724.
--

ASCENSION_ARCHIVE_REALMLIST = "127.0.0.1:3724";

function AscensionArchive_Log(msg)
	if C_Logger and C_Logger.LUA then
		C_Logger.LUA("ASCARCHIVE " .. tostring(msg));
	end
end

function AscensionArchive_ForceRealm(where)
	local want = ASCENSION_ARCHIVE_REALMLIST;
	if not want or want == "" then
		return;      -- empty string = leave the official realm alone
	end
	local had = GetCVar("realmList");
	if had ~= want then
		SetCVar("realmList", want);
		GLOBAL_REALMLIST = want;
		AscensionArchive_Log(where .. ": realmList " .. tostring(had) .. " -> " .. want);
	else
		AscensionArchive_Log(where .. ": realmList already " .. want);
	end
end

--
-- CALL SITES -- add these two lines to the existing functions. Both are needed:
-- once when the screen appears, and again immediately before the connect, so
-- that anything which rewrites the CVar in between is overruled.
--
--   function AccountLogin_OnShow()
--       AscensionArchive_ForceRealm("AccountLogin_OnShow")
--       ... existing body ...
--   end
--
--   function AccountLogin_Login()
--       PlaySound("gsLogin");
--       AscensionArchive_ForceRealm("AccountLogin_Login");   -- BEFORE the connect
--       ConnectToServer()
--       ... existing body ...
--   end
--
