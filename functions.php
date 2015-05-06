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
