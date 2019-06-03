# TCP-Bounce

Simple client and server based on the article below.

https://firstmonday.org/ojs/index.php/fm/article/view/528/449 

TL;DR - TCP header fields are relative, they don't need to be initialised, so you can set it to whatever you want.

## Note
This gets very easily defeated by things like NAT, anti-spoofing and stateful firewalls. 
