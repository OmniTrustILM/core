LOCK TABLE widget IN SHARE ROW EXCLUSIVE MODE;

UPDATE widget SET name = 'migrated';
