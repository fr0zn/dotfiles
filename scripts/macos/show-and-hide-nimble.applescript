set theApp to "Nimble Commander"

if isAppActive(theApp) then
	hideApp(theApp)
else
	activateApp(theApp)
end if


-- helper methods

on isAppActive(appName)
	tell application "System Events" to set activeApps to (get name of processes whose frontmost is true)
	appName is equal to item 1 of activeApps
end isAppActive

on activateApp(appName)
	tell application appName to activate
end activateApp

on hideApp(appName)
	tell application "Finder" to set visible of process appName to false
end hideApp
