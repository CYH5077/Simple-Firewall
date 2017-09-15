<h1><b> Simple Firewall</b></h1><br>
<h2><b><font color="Blue"> Build </font></b></h2><br>
<pre>
$ make
$ cd build 
$ sudo insmod firewall.ko
</pre><br>
<br>
<h2><b><font color="Blue"> User command </font></b></h2><br>
<pre>
Add IP rule
$ ./usercommand -rule create -saddr 192.168.0.1 -daddr 192.168.0.1

Add Port rule
$ ./usercommand -rule create -protocol tcp -sport 80 -dport 80

Show rule list
$ ./usercommand -print all

Delete rule 
$ ./usercommand -rule delete -address [rule_number]
$ ./usercommand -rule delete -address 1

Delete rule (IP)
$ ./usercommand -rule delete_ip -address 192.168.0.1

Delete rule (PORT)
$ ./usercommand -rule delete_port -address 80
</pre>
