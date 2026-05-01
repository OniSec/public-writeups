package com.htb.hosting.utils;

import java.io.File;

/* loaded from: Constants.class */
public interface Constants {
    public static final String S_USER_ID = "s_LoggedInUserUUID";
    public static final String S_USER_NAME = "s_DisplayLoggedInUsernameSafe";
    public static final String S_IS_USER_ROLE_MGR = "s_IsLoggedInUserRoleManager";
    public static final String SAFE_FILE = "safeFile";
    public static final String BASE_DIR = "baseDir";
    public static final String EDIT_FILE = "editFile";
    public static final String SELECTED_DOMAIN = "domain";
    public static final String CREATE_DOMAIN = "new";
    public static final String ROLE_MGR = "manager";
    public static final String ROLE_CUSTOMER = "customer";
    public static final String KEY_MAX_DOMAINS = "domains.max";
    public static final String KEY_DOMAIN_TEMPLATE = "domains.start-template";
    public static final File SETTINGS_FILE = new File("/etc/hosting.ini");
}