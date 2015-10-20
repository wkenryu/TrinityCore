DELETE FROM `rbac_permissions` WHERE `id` BETWEEN 837 AND 840;
INSERT INTO `rbac_permissions` (`id`, `name`) VALUES
(837, 'Command: npc spawngroup'),
(838, 'Command: npc despawngroup'),
(839, 'Command: gobject spawngroup'),
(840, 'Command: gobject despawngroup');

DELETE FROM `rbac_linked_permissions` WHERE `id` = 197 AND `linkedId` BETWEEN 837 AND 840;
INSERT INTO `rbac_linked_permissions` (`id`, `linkedId`) VALUES
(197, 837),
(197, 838),
(197, 839),
(197, 840);
