<?php
/**
 * for each hierarchy in the ldap data array, remove the 'count'
 * entry.
 */
function remove_ldap_count(&$data) {
  if(is_string($data))
    return;

  unset($data['count']);

  foreach($data as $k=>$v) {
    remove_ldap_count($data[$k]);
  }
}

/**
 * convert a shadow timestamp (days since epoch) to a unix timestamp
 */
function shadow_to_unixtime($t) {
  return (int)($t * 24 * 60 * 60);
}

/**
 * convert a unix timestamp to a shadow timestamp (days since epoch). Default:
 * today.
 */
function shadow_from_unixtime($t=null) {
  if($t === null)
    $t = time();

  return (int)($t / 24 / 60 / 60);
}
