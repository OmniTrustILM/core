create table if not exists proxy
(
    uuid          uuid         not null,
    i_author      varchar(255),
    i_cre         timestamp    not null,
    i_upd         timestamp    not null,
    name          varchar(255) not null,
    description   text,
    code          varchar(255) not null,
    status        varchar(255) not null,
    last_activity timestamp,
    primary key (uuid)
);

alter table if exists connector
    add column proxy_uuid uuid;

alter table if exists connector
    add constraint connector_to_proxy_key
    foreign key (proxy_uuid)
    references proxy;
