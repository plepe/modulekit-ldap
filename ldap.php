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


