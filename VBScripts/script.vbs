' @author Mqtth3w https://github.com/mqtth3w
' @license GPL-3.0

set x=createobject("wscript.shell")

x.run "notepad.exe"
wscript.sleep 1000
x.sendkeys "Oops, you have been hacked"
