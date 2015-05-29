CREATE TABLE IF NOT EXISTS `tablename` (
  `ASNum` int(11) NOT NULL,
  `date` date NOT NULL,
  `traffic_in` bigint(20) unsigned NOT NULL COMMENT 'big int prevents overflow',
  `traffic_out` bigint(20) unsigned NOT NULL,
  `traffic_in_peer` bigint(20) unsigned NOT NULL,
  `traffic_out_peer` bigint(20) unsigned NOT NULL,
  PRIMARY KEY (`ASNum`,`date`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
