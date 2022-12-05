rule win_quasarrat_j1 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "detects the Quasar RAT"

    strings:
        $str_1 = "DoAskElevate" ascii
        $str_2 = "DoChangeRegistryValue" ascii
        $str_3 = "DoClientDisconnect" ascii
        $str_4 = "DoClientReconnect" ascii
        $str_5 = "DoClientUninstall" ascii
        $str_6 = "DoClientUpdate" ascii
        $str_7 = "DoCloseConnection" ascii
        $str_8 = "DoCreateRegistryKey" ascii
        $str_9 = "DoCreateRegistryValue" ascii
        $str_10 = "DoDeleteRegistryKey" ascii
        $str_11 = "DoDeleteRegistryValue" ascii
        $str_12 = "DoDownloadAndExecute" ascii
        $str_13 = "DoDownloadFile" ascii
        $str_14 = "DoDownloadFileCancel" ascii
        $str_15 = "DoKeyboardEvent" ascii
        $str_16 = "DoLoadRegistryKey" ascii
        $str_17 = "DoMouseEvent" ascii
        $str_18 = "DoPathDelete" ascii
        $str_19 = "DoPathRename" ascii
        $str_20 = "DoProcessKill" ascii
        $str_21 = "DoProcessStart" ascii
        $str_22 = "DoRenameRegistryKey" ascii
        $str_23 = "DoRenameRegistryValue" ascii
        $str_24 = "DoShellExecute" ascii
        $str_25 = "DoShowMessageBox" ascii
        $str_26 = "DoShutdownAction" ascii
        $str_27 = "DoStartupItemAdd" ascii
        $str_28 = "DoStartupItemRemove" ascii
        $str_29 = "DoUploadAndExecute" ascii
        $str_30 = "DoUploadFile" ascii
        $str_31 = "DoVisitWebsite" ascii
        $str_32 = "DoWebcamStop" ascii
        $str_33 = "GetAuthentication" ascii
        $str_34 = "GetConnections" ascii
        $str_35 = "GetDesktop" ascii
        $str_36 = "GetDirectory" ascii
        $str_37 = "GetDrives" ascii
        $str_38 = "GetKeyloggerLogs" ascii
        $str_39 = "GetMonitors" ascii
        $str_40 = "GetPasswords" ascii
        $str_41 = "GetProcesses" ascii
        $str_42 = "GetStartupItems" ascii
        $str_43 = "GetSystemInfo" ascii
        $str_44 = "GetWebcam" ascii
        $str_45 = "GetWebcams" ascii
        $str_46 = "SetAuthenticationSuccess" ascii
    
    condition:
        uint16(0) == 0x5A4D and 
        40 of them
}

rule win_quasarrat_j2 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "detects the Quasar RAT"

    strings:
        $str_1 = "get_usernameField" ascii
        $str_2 = "get_timePasswordChanged" ascii
        $str_3 = "get_encryptedUsername" ascii
        $str_4 = "get_encryptedPassword" ascii
        $str_5 = "get_VistaOrHigher" ascii
        $str_6 = "get_UseProtoMembersOnly" ascii
        $str_7 = "get_UseImplicitZeroDefaults" ascii
        $str_8 = "get_TenOrHigher" ascii
        $str_9 = "get_MetadataTimeoutMilliseconds" ascii
        $str_10 = "get_EightPointOneOrHigher" ascii
        $str_11 = "get_EightOrHigher" ascii
        $str_12 = "get_DynamicType" ascii

        $quasar = "Quasar.Client.Properties.Resources" wide

        condition:
            uint16(0) == 0x5A4D and 
            8 of ($str_*) and $quasar
}