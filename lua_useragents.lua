local parserName = "lua_useragents"
local parserVersion = "2018.04.09.4"

local suspiciousUseragents = nw.createParser(parserName, "suspicious useragent detection")

nw.logDebug(parserName .. " " .. parserVersion)

--[[
    DESCRIPTION
        Lua Useragent - suspicious detection
		uses both exact match and substring matches
    VERSION
        1.0  eric.partington@rsa.com  - Initial development (with help from B. Motley)
		3.0 - Fixes for anchor start and end wildcards
		4.0 - removed nwloginfo and changed >> to -- delimeter on substring matches
    DEPENDENCIES
        something to create meta in Client metakey
		logs will need a utility parser to move user.agent to client to normalize with packets
    STANDARD INDEX KEYS
        client - reads
		analysis.session - writes
		ioc - writes
    OPTIONS
        fixme
    TODO
        fixme
--]]

--[[

Source Data
Source UA
https://github.com/Neo23x0/sigma/tree/master/rules/proxy
https://github.com/stamparm/maltrail/blob/master/misc/ua.txt

Sample Output
	APT Backspace_match
	SJZJ (compatible; MSIE 6.0; Win32)

	Metasploit_match
	X-FORWARDED-FOR

	exploit_substring_^.*wordpress hash grabber.*
	123 wordpress hash grabber abc

	exploit_substring_^.*exploit.*
	theexploiter
	
	vuln scanner and brute force_substring_^.*core%-project/1%.0.*
	the core-project/1.0 mozilla/4.0 (compatible;)
	
	Derusbi backdoor ELF https://github.com/fideliscyber/indicators/tree/master/FTA-1021_substring_^Mozilla/4%.0
	Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; 
	Media Center PC 6.0; .NET4.0C; .NET4.0E)
	
	SQL Injection_substring_^.*sqlmap.*
	sqlmap/1.0-dev (http://sqlmap.org)

--]]

keywordsMatchFull = {
    -- exact match items
	["SJZJ (compatible; MSIE 6.0; Win32)"] = "APT Backspace",
	["Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0"] = "APT GrizzlySteppe - ChopStick - US CERT https://goo.gl/1DTHwi",
	["User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC"] = "Comment Crew Miniasp",
	["Mozilla/4.0 (compatible; MSIE 7.4; Win32;32-bit)"] = "Comment Crew Miniasp",
	["webclient"] = "Naikon APT",
	["Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200"] = "Naikon APT",
	["Mozilla/4.0 (compatible; MSI 6.0;"] = "SnowGlobe Babar - yes, it is cut",
	["Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0"] = "Sofacy - Xtunnel",
	["Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/"] = "Sofacy - Xtunnel",
	["Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/2"] = "Sofacy - Xtunnel",
	["Mozilla/4.0"] = "Derusbi backdoor ELF https://github.com/fideliscyber/indicators/tree/master/FTA-1021",
	["Netscape"] = "Unit78020 Malware ",
	["Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/20100719 Firefox/1.0.7"] = "Unit78020 Malware",
	["Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Firefox/3.6.13 GTB7.1"] = "Winnti related",
	["Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"] = "Winnti related",
	["Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)"] = "APT17",
	["Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; SV1)"] = "Bronze Butler - Daserf",
	["Mozilla/4.0 (compatible; MSIE 11.0; Windows NT 6.1; SV1)"] = "Bronze Butler - Daserf",
	["^$"] = "Powershell (New-Object Net.WebClient).DownloadString",
	["Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; InfoPath.2)"] = "Cobalt Strike",
	["Mozilla/4.0 (compatible; Metasploit RSPEC)"] = "Metasploit",
	["Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)"] = "Metasploit",
	["Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"] = "Metasploit old rare",
	["Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"] = "Metasploit old rare",
	["Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)"] = "Metasploit old rare",
	["Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; SIMBAR={7DB0F6DE-8DE7-4841-9084-28FA914B0F2E}; SLCC1; .N"] = "Metasploit",
	["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"] = "Metasploit",
	["Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"] = "Metasploit",
	["Mozilla/5.0"] = "Metasploit",
	["Mozilla/4.0 (compatible; SPIPE/1.0"] = "Metasploit",
	["Mozilla/5.0 (Windows NT 6.3; rv:39.0) Gecko/20100101 Firefox/35.0"] = "Metasploit",
	["Sametime Community Agent"] = "Metasploit",
	["X-FORWARDED-FOR"] = "Metasploit",
	["DotDotPwn v2.1"] = "Metasploit",
	["SIPDROID"] = "Metasploit",
	["ruler"] = "Hacktool",
	["Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Chrome /53.0"] = "RAT DargonOK",
	["Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)"] = "RAT Used by PlugX - base-lining recommended - https://community.rsa.com/thread/185439",
	["Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0)"] = "RAT Used by PlugX - base-lining recommended - https://community.rsa.com/thread/185439",
	["Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR  1.1.4322)"] = "RAT Used by PlugX - old - https://goo.gl/Yfjtk5",
	["HttpBrowser/1.0"] = "RAT HTTPBrowser",
	["nsis_inetc (mozilla)"] = "RAT ZeroAccess",
	["Wget/1.9+cvs-stable (Red Hat modified)"] = "RAT Dyre / Upatre",
	["Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)"] = "RAT Malware Ghost419 https://goo.gl/rW1yvZ",
	["Mozilla/5.0 WinInet"] = "malware",
	["RookIE/1.0"] = "malware",
	["^M$"] = "malware HkMain",
	["Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)"] = "malware Egamipload - old UA - probable prone to false positives",
	["Mozilla/4.0 (compatible;MSIE 7.0;Windows NT 6.0)"] = "malware Yakes",
	["backdoorbot"] = "malware",
	["Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.1 (.NET CLR 3.5.30731)"] = "malware Sality",
	["Opera/8.81 (Windows NT 6.0; U; en)"] = "malware Sality",
	["Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.1 (.NET CLR 3.5.30729)"] = "malware Sality",
	["Opera"] = "malware Trojan Keragany",
	["Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)"] = "malware Fareit",
	["Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"] = "malware Webshells back connect",
	["^MSIE$"] = "malware Toby web shell",
	["Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/5.0)"] = "malware Fareit / Pony", 
	["nocase"] = "other malware",
	["Moxilla"] = "other malware",
	["AutoIt"] = "malware Suspicious - base-lining recommended",
	["IczelionDownLoad"] = "other malware",
	["user-agent"] = "badly scripted User-Agent: User-Agent:",
	["^_$"] = "badly scripted",
}

	-- substring matches - make sure table lines up with full details below (split in two parts for speed)
local keywordsSub = {
    "*wordpress hash grabber*",
    "*exploit*",
	"*core-project/1.0*",
	"Internet Explorer *",
	"*(hydra)*",
	"* arachni/*",
	"* BFAC *",
	"* brutus *",
	"* cgichk *",
	"*core-project/1.0*",
	"* crimscanner/*",
	"*datacha0s*",
	"*dirbuster*",
	"*domino hunter*",
	"*dotdotpwn*",
	"*floodgate*",
	"*get-minimal*",
	"*gootkit auto-rooter scanner*",
	"*grendel-scan*",
	"* inspath *",
	"*internet ninja*",
	"*jaascois*",
	"* zmeu *",
	"*masscan*",
	"* metis *",
	"*morfeus fucking scanner*",
	"*n-stealth*",
	"*nsauditor*",
	"*pmafind*",
	"*security scan*",
	"*springenwerk*",
	"*teh forest lobster*",
	"*toata dragostea*",
	"* vega/*",
	"*voideye*",
	"*webshag*",
	"*webvulnscan*",
	"* whcc/*",
	"* Havij",
	"*absinthe*",
	"*bsqlbf*",
	"*mysqloit*",
	"*pangolin*",
	"*sql power injector*",
	"*sqlmap*",
	"*sqlninja*",
	"*uil2pn*",
	"*<|>*",
	"*zeroup*",
	"Mozilla/5.0 (Windows NT 5.1 ; v.*",
	"* adlib/*",
	"* tiny",
	"* BGroom *",
	"* changhuatong",
	"* CholTBAgent",
	"*(Charon; Inferno)",
	"* pxyscand*",
	"* asd",
	"* mdms",
	"Win32 *",
	"*Microsoft Internet Explorer*",
	"agent *",
	"* WindowsPowerShell/*",
	"* (compatible;MSIE *",
	"*.0;Windows NT *",
	"Mozilla/3.0 *",
	"Mozilla/1.0 *",
	" Mozilla/*",
	"Mozila/*",
}

-- substring matches - full details, make sure this lines up with any changes made in above table
keywordsSubFull = {
    ["*wordpress hash grabber*"] = "exploit",
    ["*exploit*"] = "exploit",
	["*core-project/1.0*"] = "vulnscan",
	["Internet Explorer *"] = "Cobalt Strike",
	["*(hydra)*"] = "vuln scanner and brute force",
	["* arachni/*"] = "vuln scanner and brute force",
	["* BFAC *"] = "vuln scanner and brute force",
	["* brutus *"] = "vuln scanner and brute force",
	["* cgichk *"] = "vuln scanner and brute force",
	["* crimscanner/*"] = "vuln scanner and brute force",
	["*datacha0s*"] = "vuln scanner and brute force",
	["*dirbuster*"] = "vuln scanner and brute force",
	["*domino hunter*"] = "vuln scanner and brute force",
	["*dotdotpwn*"] = "vuln scanner and brute force",
	["*floodgate*"] = "vuln scanner and brute force",
	["*get-minimal*"] = "vuln scanner and brute force",
	["*gootkit auto-rooter scanner*"] = "vuln scanner and brute force",
	["*grendel-scan*"] = "vuln scanner and brute force",
	["* inspath *"] = "vuln scanner and brute force",
	["*internet ninja*"] = "vuln scanner and brute force",
	["*jaascois*"] = "vuln scanner and brute force",
	["* zmeu *"] = "vuln scanner and brute force",
	["*masscan*"] = "vuln scanner and brute force",
	["* metis *"] = "vuln scanner and brute force",
	["*morfeus fucking scanner*"] = "vuln scanner and brute force",
	["*n-stealth*"] = "vuln scanner and brute force",
	["*nsauditor*"] = "vuln scanner and brute force",
	["*pmafind*"] = "vuln scanner and brute force",
	["*security scan*"] = "vuln scanner and brute force",
	["*springenwerk*"] = "vuln scanner and brute force",
	["*teh forest lobster*"] = "vuln scanner and brute force",
	["*toata dragostea*"] = "vuln scanner and brute force",
	["* vega/*"] = "vuln scanner and brute force",
	["*voideye*"] = "vuln scanner and brute force",
	["*webshag*"] = "vuln scanner and brute force",
	["*webvulnscan*"] = "vuln scanner and brute force",
	["* whcc/*"] = "vuln scanner and brute force",
	["* Havij"] = "SQL Injection",
	["*absinthe*"] = "SQL Injection",
	["*bsqlbf*"] = "SQL Injection",
	["*mysqloit*"] = "SQL Injection",
	["*pangolin*"] = "SQL Injection",
	["*sql power injector*"] = "SQL Injection",
	["*sqlmap*"] = "SQL Injection",
	["*sqlninja*"] = "SQL Injection",
	["*uil2pn*"] = "SQL Injection",
	["*<|>*"] = "RAT Houdini / Iniduoh / njRAT",
	["*zeroup*"] = "malware W32/Renos.Downloader",
	["Mozilla/5.0 (Windows NT 5.1 ; v.*"] = "malware Kazy",
	["* adlib/*"] = "malware DriodDreamLight / DroidKungFu https://goo.gl/gcAHoh",
	["* tiny"] = "malware Trojan Downloader",
	["* BGroom *"] = "malware trojan Downloader",
	["* changhuatong"] = "malware",
	["* CholTBAgent"] = "malware",
	["*(Charon; Inferno)"] = "malware Loki Bot",
	["* pxyscand*"] = "other malware",
	["* asd"] = "other malware",
	["* mdms"] = "other malware",
	["Win32 *"] = "other malware",
	["*Microsoft Internet Explorer*"] = "other malware",
	["agent *"] = "other malware",
	["* WindowsPowerShell/*"] = "powershell",
	["* (compatible;MSIE *"] = "badly scripted typical typo - missing space",
	["*.0;Windows NT *"] = "badly scripted typical typo - missing space",
	["Mozilla/3.0 *"] = "badly scripted",
	["Mozilla/2.0 *"] = "badly scripted",
	["Mozilla/1.0 *"] = "badly scripted",
	["Mozilla *"] = "badly scripted missing slash",
	[" Mozilla/*"] = "badly scripted leading space",
	["Mozila/*"] = "badly scripted single 'l'",
}

suspiciousUseragents:setKeys({
    --nwlanguagekey.create("domain.dst"),
	--nwlanguagekey.create("direction"),
	nwlanguagekey.create("ioc", nwtypes.Text),
	nwlanguagekey.create("analysis.session", nwtypes.Text)
	
})

function suspiciousUseragents:onAgent(idx, vlu)
    local tags = {}
	local description = 0
	local foundPattern = nil
	local verdict = nil
	
	--print("looking for ua : " .. ua)

	if keywordsMatchFull[vlu] then
		-- exact match on keyword
		--print("exact match")
		--print("comment : " .. keywordsMatchFull[ua])
		--foundPattern = "pattern found: " .. keywordsMatchFull[vlu]
		verdict = "ua_match_" .. keywordsMatchFull[vlu]
		description = vlu
		
		--nw.logInfo(parserName .. " exact: " .. vlu .. ": " .. verdict)
		
		
	else
		-- substring match
		--print("substring match fallback")
		for idx, keyword in ipairs(keywordsSub) do
			-- escape any slashes
			keyword = string.gsub(keyword, "%-", "%%-")
			keyword = string.gsub(keyword, "%(", "%%(")
			keyword = string.gsub(keyword, "%)", "%%)")
			keyword = string.gsub(keyword, "%.", "%%.")
			keyword = string.gsub(keyword, "%[", "%%[")
			keyword = string.gsub(keyword, "%]", "%%]")
			keyword = string.gsub(keyword, "%?", "%%?")
			keyword = string.gsub(keyword, "%+", "%%+")
			
			--print("keyword sub : " .. keyword)

			keyword = string.gsub(keyword, "%*", "%.%*")
			--print("keyword sub : " .. keyword)
			
			--print("ua looking : " .. ua)
			
			--append ^ anchor to force match at the front of the string
			keyword = "^" .. keyword .. "$"
			
			if string.match(vlu, keyword) then
				--print("comment : " .. keywordsSubFull[keywordsSub[idx]])
				--print("keyword substring found : " .. keyword)
				--foundPattern = "pattern found: " .. keyword .. " - " .. keywordsSubFull[keywordsSub[idx]]
				verdict = "ua_substring_" .. keywordsSubFull[keywordsSub[idx]] .. "--" .. keyword
				
				--nw.logInfo(parserName .. " substring " .. vlu .. ": " .. verdict)
				
				description = vlu
				-- match on all potential matches
				-- break
			end
		end
	end
	
	-- debug
	if verdict ~= nil then 
		--nw.logInfo(parserName .. " " .. vlu .. ": " .. verdict)
		-- write out the score for that domain
		nw.createMeta(self.keys["ioc"], "suspicious_useragent")
		nw.createMeta(self.keys["analysis.session"], verdict)
		
		--nw.logInfo(parserName .. "*****************")
	end
end

suspiciousUseragents:setCallbacks({
    [nwlanguagekey.create("client")] = suspiciousUseragents.onAgent,
	--[nwlanguagekey.create("direction", nwtypes.Text)] = suspiciousUseragents.onDirection 
})