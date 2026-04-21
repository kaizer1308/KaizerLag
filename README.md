# KaizerLag

x64 hwid spoofer for newer exitlag builds. 

forked from alehacksp's original bypass. pushed it to x64 and added some iat hooking and protobuf auth spoofing. it randomizes device ids, mac addresses, and product names so you can just make a new account.

## usage
open the sln in visual studio, build for x64, and run it. it patches the process in memory. 

## notes
windows only. it injects and patches memory, so your antivirus will probably complain. ignore it or don't, up to you.