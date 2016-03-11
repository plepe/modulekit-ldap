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

function ldap_authenticate_check($user, $passwd) {
  global $ldap;
  global $ds;

  if(!$passwd)
    return "No password supplied";

  $ds=ldap_connect($ldap['host'],$ldap['port']);
  ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
  $r =ldap_search( $ds, $ldap['basedn'], 'uid=' . $user);
  if ($r) {
    $result = ldap_get_entries( $ds, $r);
    if ($result[0]) {
      if (@ldap_bind( $ds, $result[0]['dn'], $passwd) ) {
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
