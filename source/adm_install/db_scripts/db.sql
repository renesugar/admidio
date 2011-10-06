/******************************************************************************
 * SQL script with database structure
 *
 * Copyright    : (c) 2004 - 2011 The Admidio Team
 * Homepage     : http://www.admidio.org
 * License      : GNU Public License 2 http://www.gnu.org/licenses/gpl-2.0.html
 *
 ******************************************************************************/


drop table if exists %PREFIX%_announcements;
drop table if exists %PREFIX%_auto_login;
drop table if exists %PREFIX%_date_role;
drop table if exists %PREFIX%_dates;
drop table if exists %PREFIX%_files;
drop table if exists %PREFIX%_folder_roles;
drop table if exists %PREFIX%_folders;
drop table if exists %PREFIX%_guestbook_comments;
drop table if exists %PREFIX%_guestbook;
drop table if exists %PREFIX%_links;
drop table if exists %PREFIX%_list_columns;
drop table if exists %PREFIX%_lists;
drop table if exists %PREFIX%_members;
drop table if exists %PREFIX%_photos;
drop table if exists %PREFIX%_preferences;
drop table if exists %PREFIX%_role_dependencies;
drop table if exists %PREFIX%_roles;
drop table if exists %PREFIX%_rooms;
drop table if exists %PREFIX%_sessions;
drop table if exists %PREFIX%_texts;
drop table if exists %PREFIX%_user_data;
drop table if exists %PREFIX%_user_fields;
drop table if exists %PREFIX%_categories;
drop table if exists %PREFIX%_users;
drop table if exists %PREFIX%_organizations;


/*==============================================================*/
/* Table: adm_announcements                                     */
/*==============================================================*/
create table %PREFIX%_announcements
(
   ann_id                         integer       unsigned not null AUTO_INCREMENT,
   ann_org_shortname              varchar(10)   not null,
   ann_global                     boolean       not null default '0',
   ann_headline                   varchar(100)  not null,
   ann_description                text,
   ann_usr_id_create              integer       unsigned,
   ann_timestamp_create           timestamp     not null,
   ann_usr_id_change              integer       unsigned,
   ann_timestamp_change           timestamp,
   primary key (ann_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_auto_login                                        */
/*==============================================================*/
create table %PREFIX%_auto_login
(
   atl_id                         integer       unsigned not null AUTO_INCREMENT,
   atl_session_id                 varchar(35)   not null,
   atl_org_id                     integer       unsigned not null,
   atl_usr_id                     integer       unsigned not null,
   atl_last_login                 timestamp     not null,
   atl_ip_address                 varchar(15)   not null,
   primary key (atl_id)
)
engine = InnoDB
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_categories                                        */
/*==============================================================*/
create table %PREFIX%_categories
(
   cat_id                         integer       unsigned not null AUTO_INCREMENT,
   cat_org_id                     integer       unsigned,
   cat_type                       varchar(10)   not null,
   cat_name_intern                varchar(110)  not null,
   cat_name                       varchar(100)  not null,
   cat_hidden                     boolean       not null default '0',
   cat_system                     boolean       not null default '0',
   cat_default                    boolean       not null default '0',
   cat_sequence                   smallint      not null,
   cat_usr_id_create              integer       unsigned,
   cat_timestamp_create           timestamp     not null,
   cat_usr_id_change              integer       unsigned,
   cat_timestamp_change           timestamp,
   primary key (cat_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_organizations                                     */
/*==============================================================*/
create table %PREFIX%_organizations
(
   org_id                         integer       unsigned not null AUTO_INCREMENT,
   org_longname                   varchar(60)   not null,
   org_shortname                  varchar(10)   not null,
   org_org_id_parent              integer       unsigned,
   org_homepage                   varchar(60)   not null,
   primary key (org_id),
   unique (org_shortname)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_date_role                                         */
/*==============================================================*/

create table %PREFIX%_date_role
(
    dtr_id                          integer       unsigned not null AUTO_INCREMENT,
    dtr_dat_id                      integer       unsigned not null,
    dtr_rol_id                      integer       unsigned,
    primary key (dtr_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;

/*==============================================================*/
/* Table: adm_dates                                             */
/*==============================================================*/
create table %PREFIX%_dates
(
   dat_id                         integer       unsigned not null AUTO_INCREMENT,
   dat_cat_id                     integer       unsigned not null,
   dat_global                     boolean       not null default '0',
   dat_begin                      timestamp     not null,
   dat_end                        timestamp     not null,
   dat_all_day                    boolean       not null default '0',
   dat_description                text,
   dat_location                   varchar(100),
   dat_country                    varchar(100),
   dat_headline                   varchar(100)  not null,
   dat_usr_id_create              integer       unsigned,
   dat_timestamp_create           timestamp     not null,
   dat_usr_id_change              integer       unsigned,
   dat_timestamp_change           timestamp,
   dat_rol_id                     integer       unsigned,
   dat_room_id                    integer       unsigned,
   dat_max_members                integer       not null default 0,                      
   primary key (dat_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;

/*==============================================================*/
/* Table: adm_files                                             */
/*==============================================================*/
create table %PREFIX%_files
(
   fil_id                         integer       unsigned not null AUTO_INCREMENT,
   fil_fol_id                     integer       unsigned not null,
   fil_name                       varchar(255)  not null,
   fil_description                text,
   fil_locked                     boolean       not null default '0',
   fil_counter                    integer,
   fil_usr_id                     integer       unsigned,
   fil_timestamp                  timestamp     not null,
   primary key (fil_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_folder_roles                                      */
/*==============================================================*/
create table %PREFIX%_folder_roles
(
   flr_fol_id                     integer       unsigned not null,
   flr_rol_id                     integer       unsigned not null,
   primary key (flr_fol_id, flr_rol_id)
)
engine = InnoDB
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_folders                                           */
/*==============================================================*/
create table %PREFIX%_folders
(
   fol_id                         integer       unsigned not null AUTO_INCREMENT,
   fol_org_id                     integer       unsigned not null,
   fol_fol_id_parent              integer       unsigned,
   fol_type                       varchar(10)   not null,
   fol_name                       varchar(255)  not null,
   fol_description                text,
   fol_path                       varchar(255)  not null,
   fol_locked                     boolean       not null default '0',
   fol_public                     boolean       not null default '0',
   fol_usr_id                     integer       unsigned,
   fol_timestamp                  timestamp     not null,
   primary key (fol_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_guestbook                                         */
/*==============================================================*/
create table %PREFIX%_guestbook
(
   gbo_id                         integer       unsigned not null AUTO_INCREMENT,
   gbo_org_id                     integer       unsigned not null,
   gbo_name                       varchar(60)   not null,
   gbo_text                       text          not null,
   gbo_email                      varchar(50),
   gbo_homepage                   varchar(50),
   gbo_ip_address                 varchar(15)   not null,
   gbo_locked                     boolean       not null default '0',
   gbo_usr_id_create              integer       unsigned,
   gbo_timestamp_create           timestamp     not null,
   gbo_usr_id_change              integer       unsigned,
   gbo_timestamp_change           timestamp,
   primary key (gbo_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_guestbook_comments                                */
/*==============================================================*/
create table %PREFIX%_guestbook_comments
(
   gbc_id                         integer       unsigned not null AUTO_INCREMENT,
   gbc_gbo_id                     integer       unsigned not null,
   gbc_name                       varchar(60)   not null,
   gbc_text                       text          not null,
   gbc_email                      varchar(50),
   gbc_ip_address                 varchar(15)   not null,
   gbc_locked                     boolean       not null default '0',
   gbc_usr_id_create              integer       unsigned,
   gbc_timestamp_create           timestamp     not null,
   gbc_usr_id_change              integer       unsigned,
   gbc_timestamp_change           timestamp,
   primary key (gbc_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_links                                             */
/*==============================================================*/
create table %PREFIX%_links
(
   lnk_id                         integer       unsigned not null AUTO_INCREMENT,
   lnk_cat_id                     integer       unsigned not null,
   lnk_name                       varchar(255)  not null,
   lnk_description                text,
   lnk_url                        varchar(255)  not null,
   lnk_counter                    integer       not null default 0,
   lnk_usr_id_create              integer       unsigned,
   lnk_timestamp_create           timestamp     not null,
   lnk_usr_id_change              integer       unsigned,
   lnk_timestamp_change           timestamp,
   primary key (lnk_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_lists                                             */
/*==============================================================*/
create table %PREFIX%_lists
(
   lst_id                         integer       unsigned not null AUTO_INCREMENT,
   lst_org_id                     integer       unsigned not null,
   lst_usr_id                     integer       unsigned not null,
   lst_name                       varchar(255),
   lst_timestamp                  timestamp     not null,
   lst_global                     boolean       not null default '0',
   lst_default                    boolean       not null default '0',
   primary key (lst_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_list_columns                                      */
/*==============================================================*/
create table %PREFIX%_list_columns
(
   lsc_id                         integer       unsigned not null AUTO_INCREMENT,
   lsc_lst_id                     integer       unsigned not null,
   lsc_number                     smallint      not null,
   lsc_usf_id                     integer       unsigned,
   lsc_special_field              varchar(255),
   lsc_sort                       varchar(5),
   lsc_filter                     varchar(255),
   primary key (lsc_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_members                                           */
/*==============================================================*/
create table %PREFIX%_members
(
   mem_id                         integer       unsigned not null AUTO_INCREMENT,
   mem_rol_id                     integer       unsigned not null,
   mem_usr_id                     integer       unsigned not null,
   mem_begin                      date          not null,
   mem_end                        date          not null default '9999-12-31',
   mem_leader                     boolean       not null default '0',
   primary key (mem_id),
   unique (mem_rol_id, mem_usr_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;

	  
/*==============================================================*/
/* Table: adm_photos                                            */
/*==============================================================*/
create table %PREFIX%_photos
(
   pho_id                         integer       unsigned not null AUTO_INCREMENT,
   pho_org_shortname              varchar(10)   not null,
   pho_quantity                   integer		unsigned not null default 0,
   pho_name                       varchar(50)   not null,
   pho_begin                      date          not null,
   pho_end                        date          not null,
   pho_photographers              varchar(100),
   pho_locked                     boolean       not null default '0',
   pho_pho_id_parent              integer       unsigned,
   pho_usr_id_create              integer       unsigned,
   pho_timestamp_create           timestamp     not null,
   pho_usr_id_change              integer       unsigned,
   pho_timestamp_change           timestamp,
   primary key (pho_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_preferences                                       */
/*==============================================================*/
create table %PREFIX%_preferences
(
   prf_id                         integer       unsigned not null AUTO_INCREMENT,
   prf_org_id                     integer       unsigned not null,
   prf_name                       varchar(30)   not null,
   prf_value                      varchar(255),
   primary key (prf_id),
   unique (prf_org_id, prf_name)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_role_dependencies                                 */
/*==============================================================*/
create table %PREFIX%_role_dependencies
(
   rld_rol_id_parent              integer       unsigned not null,
   rld_rol_id_child               integer       unsigned not null,
   rld_comment                    text,
   rld_usr_id                     integer       unsigned,
   rld_timestamp                  timestamp     not null,
   primary key (rld_rol_id_parent, rld_rol_id_child)
)
engine = InnoDB
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_roles                                             */
/*==============================================================*/
create table %PREFIX%_roles
(
   rol_id                         integer       unsigned not null AUTO_INCREMENT,
   rol_cat_id                     integer       unsigned not null,
   rol_name                       varchar(30)   not null,
   rol_description                varchar(255),
   rol_assign_roles               boolean       not null default '0',
   rol_approve_users              boolean       not null default '0',
   rol_announcements              boolean       not null default '0',
   rol_dates                      boolean       not null default '0',
   rol_download                   boolean       not null default '0',
   rol_edit_user                  boolean       not null default '0',
   rol_guestbook                  boolean       not null default '0',
   rol_guestbook_comments         boolean       not null default '0',
   rol_inventory				  boolean       not null default '0',
   rol_mail_to_all                boolean       not null default '0',
   rol_mail_this_role             smallint      not null default 0,
   rol_photo                      boolean       not null default '0',
   rol_profile                    boolean       not null default '0',
   rol_weblinks                   boolean       not null default '0',
   rol_this_list_view             smallint      not null default 0,
   rol_all_lists_view             boolean       not null default '0',
   rol_start_date                 date,
   rol_start_time                 time,
   rol_end_date                   date,
   rol_end_time                   time,
   rol_weekday                    smallint,
   rol_location                   varchar(30),
   rol_max_members                integer,
   rol_cost                       float         unsigned,
   rol_cost_period				  smallint,
   rol_usr_id_create              integer       unsigned,
   rol_timestamp_create           timestamp     not null,
   rol_usr_id_change              integer       unsigned,
   rol_timestamp_change           timestamp,
   rol_valid                      boolean       not null default '1',
   rol_system                     boolean       not null default '0',
   rol_visible                    boolean       not null default '1',
   primary key (rol_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_rooms                                             */
/*==============================================================*/

create table %PREFIX%_rooms
(
    room_id                       integer       unsigned not null AUTO_INCREMENT,
    room_name                     varchar(50)   not null,
    room_description              varchar(255),
    room_capacity                 integer       not null,
    room_overhang                 integer,
    room_usr_id_create            integer       unsigned,
    room_timestamp_create         timestamp     not null,
    room_usr_id_change            integer       unsigned,
    room_timestamp_change         timestamp,
    primary key (room_id)                                                                       
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_sessions                                          */
/*==============================================================*/
create table %PREFIX%_sessions
(
   ses_id                         integer       unsigned not null AUTO_INCREMENT,
   ses_usr_id                     integer       unsigned default NULL,
   ses_org_id                     integer       unsigned not null,
   ses_session_id                 varchar(35)   not null,
   ses_begin                      timestamp     not null,
   ses_timestamp                  timestamp     not null,
   ses_ip_address                 varchar(15)   not null,
   ses_binary                     blob,
   ses_renew                      smallint      not null default 0,
   primary key (ses_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;

create index IDX_SESSION_ID on %PREFIX%_sessions (ses_session_id);


/*==============================================================*/
/* Table: adm_texts                                             */
/*==============================================================*/
create table %PREFIX%_texts
(
   txt_id                         integer       unsigned not null AUTO_INCREMENT,
   txt_org_id                     integer       unsigned not null,
   txt_name                       varchar(30)   not null,
   txt_text                       text,
   primary key (txt_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_user_fields                                       */
/*==============================================================*/
create table %PREFIX%_user_fields
(
   usf_id                         integer       unsigned not null AUTO_INCREMENT,
   usf_cat_id                     integer       unsigned not null,
   usf_type                       varchar(30)   not null,
   usf_name_intern                varchar(110)  not null,
   usf_name                       varchar(100)  not null,
   usf_description                text,
   usf_value_list                 text,
   usf_icon 					  varchar(255),
   usf_url	 				      varchar(255),
   usf_system                     boolean       not null default '0',
   usf_disabled                   boolean       not null default '0',
   usf_hidden                     boolean       not null default '0',
   usf_mandatory                  boolean       not null default '0',
   usf_sequence                   smallint      not null,
   usf_usr_id_create              integer       unsigned,
   usf_timestamp_create           timestamp     not null,
   usf_usr_id_change              integer       unsigned,
   usf_timestamp_change           timestamp,
   primary key (usf_id),
   unique (usf_name_intern)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_user_data                                         */
/*==============================================================*/
create table %PREFIX%_user_data
(
   usd_id                         integer       unsigned not null AUTO_INCREMENT,
   usd_usr_id                     integer       unsigned not null,
   usd_usf_id                     integer       unsigned not null,
   usd_value                      varchar(255),
   primary key (usd_id),
   unique (usd_usr_id, usd_usf_id)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Table: adm_users                                             */
/*==============================================================*/
create table %PREFIX%_users
(
   usr_id                         integer       unsigned not null AUTO_INCREMENT,
   usr_login_name                 varchar(35),
   usr_password                   varchar(35),
   usr_new_password               varchar(35),
   usr_photo                      blob,
   usr_text                       text,
   usr_activation_code            varchar(10),
   usr_last_login                 timestamp,
   usr_actual_login               timestamp,
   usr_number_login               integer       not null default 0,
   usr_date_invalid               timestamp,
   usr_number_invalid             smallint      not null default 0,
   usr_usr_id_create              integer       unsigned,
   usr_timestamp_create           timestamp     not null,
   usr_usr_id_change              integer       unsigned,
   usr_timestamp_change           timestamp,
   usr_valid                      boolean       not null default '0',
   usr_reg_org_shortname          varchar(10),
   primary key (usr_id),
   unique (usr_login_name)
)
engine = InnoDB
auto_increment = 1
default character set = utf8
collate = utf8_unicode_ci;


/*==============================================================*/
/* Constraints                                                  */
/*==============================================================*/
alter table %PREFIX%_announcements add constraint %PREFIX%_FK_ANN_ORG foreign key (ann_org_shortname)
      references %PREFIX%_organizations (org_shortname) on delete restrict on update restrict;
alter table %PREFIX%_announcements add constraint %PREFIX%_FK_ANN_USR_CREATE foreign key (ann_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_announcements add constraint %PREFIX%_FK_ANN_USR_CHANGE foreign key (ann_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

alter table %PREFIX%_auto_login add constraint %PREFIX%_FK_ATL_USR foreign key (atl_usr_id)
      references %PREFIX%_users (usr_id) on delete restrict on update restrict;
alter table %PREFIX%_auto_login add constraint %PREFIX%_FK_ATL_ORG foreign key (atl_org_id)
      references %PREFIX%_organizations (org_id) on delete restrict on update restrict;

alter table %PREFIX%_categories add constraint %PREFIX%_FK_CAT_ORG foreign key (cat_org_id)
      references %PREFIX%_organizations (org_id) on delete restrict on update restrict;
alter table %PREFIX%_categories add constraint %PREFIX%_FK_CAT_USR_CREATE foreign key (cat_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_categories add constraint %PREFIX%_FK_CAT_USR_CHANGE foreign key (cat_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

alter table %PREFIX%_date_role add constraint %PREFIX%_FK_DTR_DAT foreign key (dtr_dat_id)
      references %PREFIX%_dates (dat_id) on delete restrict on update restrict;
alter table %PREFIX%_date_role add constraint %PREFIX%_FK_DTR_ROL foreign key (dtr_rol_id)
      references %PREFIX%_roles (rol_id) on delete restrict on update restrict;

alter table %PREFIX%_dates add constraint %PREFIX%_FK_DAT_CAT foreign key (dat_cat_id)
      references %PREFIX%_categories (cat_id) on delete restrict on update restrict;
alter table %PREFIX%_dates add constraint %PREFIX%_FK_DAT_ROL foreign key (dat_rol_id)
      references %PREFIX%_roles (rol_id) on delete restrict on update restrict;
alter table %PREFIX%_dates add constraint %PREFIX%_FK_DAT_ROOM foreign key (dat_room_id)
      references %PREFIX%_rooms (room_id) on delete set null on update restrict;
alter table %PREFIX%_dates add constraint %PREFIX%_FK_DAT_USR_CREATE foreign key (dat_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_dates add constraint %PREFIX%_FK_DAT_USR_CHANGE foreign key (dat_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
      
alter table %PREFIX%_files add constraint %PREFIX%_FK_FIL_FOL foreign key (fil_fol_id)
      references %PREFIX%_folders (fol_id) on delete restrict on update restrict;
alter table %PREFIX%_files add constraint %PREFIX%_FK_FIL_USR foreign key (fil_usr_id)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

alter table %PREFIX%_folder_roles add constraint %PREFIX%_FK_FLR_FOL foreign key (flr_fol_id)
      references %PREFIX%_folders (fol_id) on delete restrict on update restrict;
alter table %PREFIX%_folder_roles add constraint %PREFIX%_FK_FLR_ROL foreign key (flr_rol_id)
      references %PREFIX%_roles (rol_id) on delete restrict on update restrict;

alter table %PREFIX%_folders add constraint %PREFIX%_FK_FOL_ORG foreign key (fol_org_id)
      references %PREFIX%_organizations (org_id) on delete restrict on update restrict;
alter table %PREFIX%_folders add constraint %PREFIX%_FK_FOL_FOL_PARENT foreign key (fol_fol_id_parent)
      references %PREFIX%_folders (fol_id) on delete restrict on update restrict;
alter table %PREFIX%_folders add constraint %PREFIX%_FK_FOL_USR foreign key (fol_usr_id)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

alter table %PREFIX%_guestbook add constraint %PREFIX%_FK_GBO_ORG foreign key (gbo_org_id)
      references %PREFIX%_organizations (org_id) on delete restrict on update restrict;
alter table %PREFIX%_guestbook add constraint %PREFIX%_FK_GBO_USR_CREATE foreign key (gbo_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_guestbook add constraint %PREFIX%_FK_GBO_USR_CHANGE foreign key (gbo_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

alter table %PREFIX%_guestbook_comments add constraint %PREFIX%_FK_GBC_GBO foreign key (gbc_gbo_id)
      references %PREFIX%_guestbook (gbo_id) on delete restrict on update restrict;
alter table %PREFIX%_guestbook_comments add constraint %PREFIX%_FK_GBC_USR_CREATE foreign key (gbc_usr_id_create)
      references %PREFIX%_users (usr_id) on delete restrict on update restrict;
alter table %PREFIX%_guestbook_comments add constraint %PREFIX%_FK_GBC_USR_CHANGE foreign key (gbc_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

	  alter table %PREFIX%_links add constraint %PREFIX%_FK_LNK_CAT foreign key (lnk_cat_id)
      references %PREFIX%_categories (cat_id) on delete restrict on update restrict;
alter table %PREFIX%_links add constraint %PREFIX%_FK_LNK_USR_CREATE foreign key (lnk_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_links add constraint %PREFIX%_FK_LNK_USR_CHANGE foreign key (lnk_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

alter table %PREFIX%_lists add constraint %PREFIX%_FK_LST_USR foreign key (lst_usr_id)
      references %PREFIX%_users (usr_id) on delete restrict on update restrict;
alter table %PREFIX%_lists add constraint %PREFIX%_FK_LST_ORG foreign key (lst_org_id)
      references %PREFIX%_organizations (org_id) on delete restrict on update restrict;

alter table %PREFIX%_list_columns add constraint %PREFIX%_FK_LSC_LST foreign key (lsc_lst_id)
      references %PREFIX%_lists (lst_id) on delete restrict on update restrict;
alter table %PREFIX%_list_columns add constraint %PREFIX%_FK_LSC_USF foreign key (lsc_usf_id)
      references %PREFIX%_user_fields (usf_id) on delete restrict on update restrict;

alter table %PREFIX%_members add constraint %PREFIX%_FK_MEM_ROL foreign key (mem_rol_id)
      references %PREFIX%_roles (rol_id) on delete restrict on update restrict;
alter table %PREFIX%_members add constraint %PREFIX%_FK_MEM_USR foreign key (mem_usr_id)
      references %PREFIX%_users (usr_id) on delete restrict on update restrict;

alter table %PREFIX%_organizations add constraint %PREFIX%_FK_ORG_ORG_PARENT foreign key (org_org_id_parent)
      references %PREFIX%_organizations (org_id) on delete set null on update restrict;

alter table %PREFIX%_photos add constraint %PREFIX%_FK_PHO_PHO_PARENT foreign key (pho_pho_id_parent)
      references %PREFIX%_photos (pho_id) on delete set null on update restrict;
alter table %PREFIX%_photos add constraint %PREFIX%_FK_PHO_ORG foreign key (pho_org_shortname)
      references %PREFIX%_organizations (org_shortname) on delete restrict on update restrict;
alter table %PREFIX%_photos add constraint %PREFIX%_FK_PHO_USR_CREATE foreign key (pho_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_photos add constraint %PREFIX%_FK_PHO_USR_CHANGE foreign key (pho_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

alter table %PREFIX%_preferences add constraint %PREFIX%_FK_PRF_ORG foreign key (prf_org_id)
      references %PREFIX%_organizations (org_id) on delete restrict on update restrict;
	  
alter table %PREFIX%_role_dependencies add constraint %PREFIX%_FK_RLD_ROL_CHILD foreign key (rld_rol_id_child)
      references %PREFIX%_roles (rol_id) on delete restrict on update restrict;
alter table %PREFIX%_role_dependencies add constraint %PREFIX%_FK_RLD_ROL_PARENT foreign key (rld_rol_id_parent)
      references %PREFIX%_roles (rol_id) on delete restrict on update restrict;
alter table %PREFIX%_role_dependencies add constraint %PREFIX%_FK_RLD_USR foreign key (rld_usr_id)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

alter table %PREFIX%_roles add constraint %PREFIX%_FK_ROL_CAT foreign key (rol_cat_id)
      references %PREFIX%_categories (cat_id) on delete restrict on update restrict;
alter table %PREFIX%_roles add constraint %PREFIX%_FK_ROL_USR_CREATE foreign key (rol_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_roles add constraint %PREFIX%_FK_ROL_USR_CHANGE foreign key (rol_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;

alter table %PREFIX%_rooms add constraint %PREFIX%_FK_ROOM_USR_CREATE foreign key (room_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_rooms add constraint %PREFIX%_FK_ROOM_USR_CHANGE foreign key (room_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
	  
alter table %PREFIX%_sessions add constraint %PREFIX%_FK_SES_ORG foreign key (ses_org_id)
      references %PREFIX%_organizations (org_id) on delete restrict on update restrict;
alter table %PREFIX%_sessions add constraint %PREFIX%_FK_SES_USR foreign key (ses_usr_id)
      references %PREFIX%_users (usr_id) on delete restrict on update restrict;
	  
alter table %PREFIX%_texts add constraint %PREFIX%_FK_TXT_ORG foreign key (txt_org_id)
      references %PREFIX%_organizations (org_id) on delete restrict on update restrict;

alter table %PREFIX%_user_fields add constraint %PREFIX%_FK_USF_CAT foreign key (usf_cat_id)
      references %PREFIX%_categories (cat_id) on delete restrict on update restrict;
alter table %PREFIX%_user_fields add constraint %PREFIX%_FK_USF_USR_CREATE foreign key (usf_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_user_fields add constraint %PREFIX%_FK_USF_USR_CHANGE foreign key (usf_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
	  
alter table %PREFIX%_user_data add constraint %PREFIX%_FK_USD_USF foreign key (usd_usf_id)
      references %PREFIX%_user_fields (usf_id) on delete restrict on update restrict;
alter table %PREFIX%_user_data add constraint %PREFIX%_FK_USD_USR foreign key (usd_usr_id)
      references %PREFIX%_users (usr_id) on delete restrict on update restrict;
	  
alter table %PREFIX%_users add constraint %PREFIX%_FK_USR_ORG_REG foreign key (usr_reg_org_shortname)
      references %PREFIX%_organizations (org_shortname) on delete restrict on update restrict;
alter table %PREFIX%_users add constraint %PREFIX%_FK_USR_USR_CREATE foreign key (usr_usr_id_create)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;
alter table %PREFIX%_users add constraint %PREFIX%_FK_USR_USR_CHANGE foreign key (usr_usr_id_change)
      references %PREFIX%_users (usr_id) on delete set null on update restrict;