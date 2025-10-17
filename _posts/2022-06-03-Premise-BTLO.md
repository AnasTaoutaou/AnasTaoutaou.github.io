---
title: "Analyzing network logs using Wireshark: Premise"
date: 2022-06-03 00:25:00 -0600
categories: [WriteUps, blueteamlabs]
tags: [blueteam,wireshark,pcap]     # TAG names should always be lowercase
---

In these series of blog posts, I will dive into some blueteam assessments where I'm given scenarios of breaches to investigate. Let's take a look on how to analyze a pcap file for more details on a compromise.

The format here is that you are given tools and evidence and you are to answer questions about the breach.

We start by firing up Wireshark and loading up the LAB.pcap file.

![Screenshot](/images/Screenshot_2022-06-04_06-35-58.png)
![Screenshot](/images/Screenshot_2022-06-04_06-36-50.png)

We see that we have a total of 9553 packets, so your job as a Security/SOC analyst is to comb through all of that and filter out all the garbage.

Let's start by reading some stats:

![Screenshot](/images/Screenshot_2022-06-04_06-39-44.png)
![Screenshot](/images/Screenshot_2022-06-04_06-39-59.png)

We see that `192.168.1.8` and `192.168.1.9` have the most traffic so I'll look into them. I can use the following filter to only see traffic from both ips. : `ip.addr == 192.168.1.8 || ip.addr == 192.168.1.9`.

The results are still not satisfactory so I'll only leave communications between the two, now there could be a better way to do this 
but this query worked fine for me: `(ip.src == 192.168.1.9 && ip.dst == 192.168.1.8) || (ip.src == 192.168.1.8 && ip.dst == 192.168.1.9)`. We start to get some good stuff right after.

![Screenshot](/images/Screenshot_2022-06-04_06-49-51.png)

# Question1: What is the full filename of the initial payload file?
The file in question might be the first thing that popped out: "INVOICE_2021937.pdf.bat". Mainly because invoices aren't supposed to be `.bat` files :/ but let's take a closer look.

![Screenshot](/images/Screenshot_2022-06-04_06-51-52.png)
![Screenshot](/images/Screenshot_2022-06-04_06-52-00.png)

That is absolutly malicious so let's move on to the next question.

Answer: INVOICE_2021937.pdf.bat

# Question2: What is the name of the module used to serve the malicious payload?

If you do pentesting a lot, you use this module too. But looking at the headers of the response of which the malware was served we see the module in the `Server:` header: SimpleHTTPServer. Next question.

![Screenshot](/images/header.png)

Answer: SimpleHTTPServer

# Question3: Analysing the traffic, what is the attacker's IP address?

Since the malicious file was transfered from the attacker's machine, we simply look at the packet and we see the destination of the request, and it's `192.168.1.9`.

Answer: 192.168.1.9

# Question4: Now that you know the payload name and the module used to deliver the malicious files, what is the URL that was embedded in the malicious email?

This was just common sense or more like putting the pieces together but here's a recap of what we know:

	- It was served via HTTP
	- It came from 192.168.1.9
	- Destination of the request was port 443
	- Name of file is INVOICE_2021937.pdf.bat

So to put it all together: `http://192.168.1.9:443/INVOICE_2021937.pdf.bat`

Answer: http://192.168.1.9:443/INVOICE_2021937.pdf.bat

# Question5: Find the PowerShell launcher string?

We can see it clearly here (although usually we investigate the base64 code): 

![Screenshot](/images/ps.png)

Answer: powershell -noP -sta -w 1 -enc

# Question6: What is the default user agent being used for communications?

Looking again at the previous image, we look at the User Agent header and we see that the attacker is fond of open source and is using Mozilla/5.0. Next.

![Screenshot](/images/header.png)

Answer: Mozilla/5.0

# Question7: You are seeing a lot of HTTP traffic. What is the name of a process where malware communicates with a central server asking for instructions at set time intervals?

This is more of common knowledge but when a compromised host wants to say "hey I'm alive what's next" to the command&control server, it sends a beacon.

Answer: beaconing

# Question8: What is the URI containing ‘login’ that the victim machine is communicating to?

Since we're dealing with URIs, we can try to add another filter to focus on HTTP traffic, simply append `&& http` to your query.

![Screenshot](/images/Screenshot_2022-06-04_07-10-10.png)

We see that it is: `/login/process.php`

Answer: /login/process.php

# Question9: What is the name of the popular post-exploitation framework used for command-and-control communication?

We can google something like "c2 /login/process.php" and we get Empire.

![Screenshot](/images/Screenshot_2022-06-04_07-11-45.png)

Answer: Empire

# Question10: It is believed that data is being exfiltrated. Investigate and provide the decoded password?

We can extract data with another wireshark variant provided: `tshark`.

Let's run the following command: `.\tshark.lnk -r c:\users\btlotest\desktop\investigations\LAB.pcap -T fields -e data > data.txt`

Upon looking into data.txt we find an long string of new-lined hex numbers. We can use CyberChef which was provided to us to use.

P.S. I had to remove duplicated chars to make it work.

![Screenshot](/images/Screenshot_2022-06-04_07-25-30.png)
![Screenshot](/images/Screenshot_2022-06-04_07-25-55.png)
![Screenshot](/images/Screenshot_2022-06-04_07-43-24.png)

"P.a.s.s.w.o.r.d. .f.o.r. .m.y. .$.s.e.c.-.a.c.c.o.u.n.t.:. .Y.0.u.t.h.i.n.k.y.0.u.c.A.n.c.4.t.c.h.m."
We get answers for the last 2 questions.

Answer: Y0uthinky0ucAnc4tchm3$$

# Question11: What is the account’s username?

Answer: $sec-account


