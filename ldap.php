<?php
// find next uid after highest uid in range
function ldap_find_nextuid($uid_range) {
  global $ldap;

  $r=ldap_search($ldap['conn'], $ldap['ubasedn'], 'objectClass=*', array("uidNumber"));
  if(!$r)
    exit();

  $result=ldap_get_entries($ldap['conn'], $r);
  $uid=$uid_range[0]-1;
  foreach($result as $entry) {
    if(isset($entry['uidnumber'])) {
      $curr_uid=$entry['uidnumber'][0];
      if(($curr_uid>=$uid_range[0])&&($curr_uid<=$uid_range[1])) {
	if($curr_uid>$uid)
	  $uid=$curr_uid;
      }
    }
  }
  $uid++;

  if($uid > $uid_range[1])
    return null;

  return $uid;
}

// find next gid after highest uid in range
function ldap_find_nextgid($gid_range) {
  global $ldap;

  $r=ldap_search($ldap['conn'], $ldap['gbasedn'], 'objectClass=*', array("gidNumber"));
  if(!$r)
    exit();

  $result=ldap_get_entries($ldap['conn'], $r);
  $gid=$gid_range[0]-1;
  foreach($result as $entry) {
    if(isset($entry['gidnumber'])) {
      $curr_gid=$entry['gidnumber'][0];
      if(($curr_gid>=$gid_range[0])&&($curr_gid<=$gid_range[1])) {
	if($curr_gid>$gid)
	  $gid=$curr_gid;
      }
    }
  }
  $gid++;

  if($gid > $gid_range[1])
    return null;

  return $gid;
}

// find first unused uid in uid range
function ldap_find_freeuid($uid_range) {
  global $ldap;
  $uid_list=array();

  $r=ldap_search($ldap['conn'], $ldap['mbasedn'], '(objectClass=*)', array("uidNumber"));
  if(!$r)
    exit();

  $result=ldap_get_entries($ldap['conn'], $r);
  $uid=$uid_range[0]-1;
  foreach($result as $entry) {
    if(isset($entry['uidnumber'])) {
      $uid=$entry['uidnumber'][0];
      if(($uid>=$uid_range[0])&&($uid<=$uid_range[1]))
	$uid_list[]=$uid;
    }
  }

  for($uid=$uid_range[0]; $uid<=$uid_range[1]; $uid++) {
    if(!in_array($uid, $uid_list))
      return $uid;
  }

  return false;
}

// connect to ldap as admin
function ldap_admin_connect() {
  global $ldap;
  $stderr = fopen('php://stderr', 'w');
  $try=0;

  ldap_set_option($ldap['conn'], LDAP_OPT_PROTOCOL_VERSION, 3);

  do {
    $try++;

    // Get admin password for LDAP, connect
    system("stty -echo");
    fputs($stderr, "LDAP Admin password: ");
    $admin_passwd=fscanf(STDIN, "%s");
    $admin_passwd=$admin_passwd[0];
    fputs($stderr, "\n");
    system("stty echo");

    @$result=ldap_bind($ldap['conn'], "cn={$ldap['admin_name']},{$ldap['basedn']}", $admin_passwd);

    if(!$result)
      fputs($stderr, "Error connecting to LDAP: ".ldap_error($ldap['conn'])."\n");

  } while((!$result)&&($try<3));

  if(!$result) {
    fputs($stderr, "!! Connecting to LDAP as admin failed.\n");
    exit();
  }

  return $result;
}

function ldap_user_get_fullname($username) {
  global $ldap;

  $r=ldap_search($ldap['conn'], $ldap['ubasedn'], "uid={$username}", array("displayName"));
  if(!$r)
    return null;
  
  $result=ldap_get_entries($ldap['conn'], $r);
  if($result['count']==0)
    return null;

  return $result[0]['displayname'][0];
}

/**
 * return a list of all groups (as ldap_search result)
 * @param string $username Username of the user
 * @param string[] $attributes list of attributes to return
 * @return mixed[] an ldap_search result including 'count' values
 */
function ldap_user_groups ($username, $attributes=null) {
  global $ldap;

  // First get gidNumber from user account
  $r = ldap_search($ldap['conn'], $ldap['ubasedn'], "uid={$username}", array('gidNumber'));
  if(!$r) {
    trigger_error('ldap_user_groups: ' . ldap_error($ldap['conn']), E_USER_WARNING);
    return null;
  }

  $user = ldap_get_entries($ldap['conn'], $r);

  if ($user['count'] === 0) {
    trigger_error("ldap_user_groups: no such user", E_USER_WARNING);
    return null;
  }

  $gidNumber = $user[0]['gidnumber'][0];

  // query for groups with user membership and the group with the user's gidNumber
  if ($attributes === null)
    $r = ldap_search($ldap['conn'], $ldap['gbasedn'], "(|(memberUid={$username})(gidNumber={$gidNumber}))");
  else
    $r = ldap_search($ldap['conn'], $ldap['gbasedn'], "(|(memberUid={$username})(gidNumber={$gidNumber}))", $attributes);

  if(!$r) {
    trigger_error('ldap_user_groups: ' . ldap_error($ldap['conn']), E_USER_WARNING);
    return null;
  }

  // Done
  return ldap_get_entries($ldap['conn'], $r);
}

function ldap_authenticate_check($user, $passwd) {
  global $ldap;
  global $ds;

  if(!$passwd)
    return "No password supplied";

  $ds = ldap_connect($ldap['host'],$ldap['port']);
  if (!$ds) {
    return "Can't connect to server";
  }
  ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

  if ($ldap['bind_user']) {
    if (!ldap_bind($ds, $ldap['bind_user'], $ldap['bind_password']))
      return "Can't bind to server";
  }

  $r =ldap_search( $ds, $ldap['basedn'], 'uid=' . $user);
  if ($r) {
    $result = ldap_get_entries( $ds, $r);
    if ($result[0]) {
      if (@ldap_bind( $ds, $result[0]['dn'], $passwd) ) {
        // reload account data as authenticated user
        $r = ldap_search( $ds, $ldap['basedn'], 'uid=' . $user);
        $result = ldap_get_entries( $ds, $r);

	return $result[0];
      }
      else
	return ldap_error($ds);
    }
  }

  return "Invalid credentials";
}

function ldap_shadowExpire_date($t=null) {
  if($t === null)
    $t = time();

  return (int)($t / 24 / 60 / 60);
}

function ldap_shadowExpire_timestamp($expire_date) {
  return (int)$expire_date * 24 * 60 * 60;
}

function ldap_get_expiry_timestamp($user) {
  $ret = false;
  if($user['shadowexpire'])
    $ret = ldap_shadowExpire_timestamp($user['shadowexpire'][0]);
  if($user['sambakickofftime'] &&
     (($ret === false) || ($user['sambakickofftime'][0] < $ret)))
    $ret = (int)$user['sambakickofftime'][0];

  return $ret;
}

/**
 * reread account data
 */
function ldap_reread_account(&$account) {
  global $ldap;

  $ldap_attributes = array();
  foreach($account as $k => $v) {
    if(!in_array($k, array('dn', 'count')) && !is_int($k))
      $ldap_attributes[] = $k;
  }

  $r=ldap_search($ldap['conn'], $account['dn'], 'objectClass=*', $ldap_attributes);
  $account = ldap_get_entries($ldap['conn'], $r);
  $account = $account[0];
}

/**
 * activate password
 * @return boolean/string true=success, false=not deactivated, string=error occured
 */
function ldap_shadow_account_activate(&$account) {
  global $ldap;

  if(!in_array('userpassword', $account))
    return false;

  if(preg_match("/^(\{[A-Z0-9]*\})(\!)?(.*)$/", $account['userpassword'][0], $m)) {
    // if ! is in userpassword hash, account is deactivated
    if($m[2] == "!") {
      $ldap_mod_replace = array(
        'userpassword' => "{$m[1]}{$m[3]}"
      );

      ldap_mod_replace($ldap['conn'], $account['dn'], $ldap_mod_replace);

      ldap_reread_account($account);

      return true;
    }
    else
      return false;
  }
  else
    return "Can't parse field userPassword";
}

function ldap_shadow_account_deactivate(&$account) {
  global $ldap;

  if(!in_array('userpassword', $account))
    return false;

  if(preg_match("/^(\{[A-Z0-9]*\})(\!)?(.*)$/", $account['userpassword'][0], $m)) {
    // if ! is in userpassword hash, account is already deactivated
    if($m[2] != "!") {
      $ldap_mod_replace = array(
        'userpassword' => "{$m[1]}!{$m[3]}"
      );

      ldap_mod_replace($ldap['conn'], $account['dn'], $ldap_mod_replace);

      ldap_reread_account($account);

      return true;
    }
    else
      return false;
  }
  else
    return "Can't parse field userPassword";
}

/**
 * activate password
 * @return boolean/string true=success, false=not deactivated, string=error occured
 */
function ldap_samba_account_activate(&$account) {
  global $ldap;

  if(!in_array("sambaSamAccount", $account['objectclass']))
    return false;

  if(!in_array('sambaacctflags', $account))
    return false;

  // if sambaAcctFlags contains 'D', account is deactivated
  if(strpos($account['sambaacctflags'][0], "D") !== false) {
    $ldap_mod_replace = array(
      'sambaacctflags' => sprintf("[%16s]", trim(strtr(substr($account['sambaacctflags'][0], 1, -1), array("D" => "")))),
    );

    ldap_mod_replace($ldap['conn'], $account['dn'], $ldap_mod_replace);

    ldap_reread_account($account);

    return true;
  }

  return false;
}

/**
 * deactivate password
 * @return boolean/string true=success, false=not deactivated, string=error occured
 */
function ldap_samba_account_deactivate(&$account) {
  global $ldap;

  if(!in_array("sambaSamAccount", $account['objectclass']))
    return false;

  if(!in_array('sambaacctflags', $account))
    return false;

    // if sambaAcctFlags contains 'D', account is already deactivated
  if(strpos($account['sambaacctflags'][0], "D") === false) {
    $ldap_mod_replace = array(
      'sambaacctflags' => sprintf("[%16s]", trim(substr($account['sambaacctflags'][0], 1, -1)) . "D"),
    );

    ldap_mod_replace($ldap['conn'], $account['dn'], $ldap_mod_replace);

    ldap_reread_account($account);

    return true;
  }

  return false;
}

/**
 * @return boolean/null true=active false=locked null=can't tell
 */
function ldap_shadow_account_isactive($account) {
  if(!in_array('userpassword', $account))
    return null;

  if(!preg_match("/^(\{[A-Z0-9]*\})(\!)?(.*)$/", $account['userpassword'][0], $m))
    return null;

  return $m[2] != "!";
}

/**
 * @return boolean/null true=active false=locked null=can't tell
 */
function ldap_samba_account_isactive($account) {
  if(!in_array('objectclass', $account))
    return null;

  // no samba active -> locked
  if(!in_array("sambaSamAccount", $account['objectclass']))
    return false;

  if(!in_array('sambaacctflags', $account))
    return null;

  // if sambaAcctFlags contains 'D', account is deactivated
  return strpos($account['sambaacctflags'][0], "D") === false;
}

/**
 * @return list of all users matching the given $str
 */
$ldap_all_user_names = null;
function ldap_search_user ($str) {
  global $ldap_all_user_names;
  global $ldap;

  // build user database
  if ($ldap_all_user_names === null) {
    $r = ldap_search($ldap['conn'], $ldap['ubasedn'], 'objectClass=*', array('cn', 'displayname'));
    $result = ldap_get_entries($ldap['conn'], $r);
    $ldap_all_user_names = array();
    for ($i = 0; $i < $result['count']; $i++) {
      if (isset($result[$i]['displayname']) && isset($result[$i]['cn']))
        $ldap_all_user_names[$result[$i]['cn'][0]] = $result[$i]['displayname'][0];
    }
  }

  // build search regexp
  $regexp = '';
  for ($i = 0; $i < strlen($str); $i++) {
    $c = substr($str, $i, 1);

    switch (strtolower($c)) {
      case 'a':
      case 'ä':
      case 'á':
        $r = '(a|ä|á|ae)'; break;
      case 'c':
        $r = '(c|č|ç)'; break;
      case 'e':
      case 'é':
        $r = '(e|é)'; break;
      case 'i':
      case 'í':
        $r = '(i|í)'; break;
      case 'o':
      case 'ö':
      case 'ó':
        $r = '(o|ö|ó|oe)'; break;
      case 'r':
      case 'ř':
        $r = '(r|ř)'; break;
      case 's':
      case 'š':
        $r = '(s|š)'; break;
      case 'u':
      case 'ü':
      case 'ú':
        $r = '(u|ü|ú|ue)'; break;
      default:
        $r = $c;
    }

    $regexp .= $r;
  }

  // now query
  $ret = array();
  foreach ($ldap_all_user_names as $uid => $name) {
    if (preg_match("/$regexp/i", $name)) {
      $ret[$uid] = $name;
    }
    else if (preg_match("/$regexp/i", $uid)) {
      $ret[$uid] = $name;
    }
  }

  return $ret;
}
