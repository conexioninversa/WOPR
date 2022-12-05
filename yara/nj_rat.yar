rule win_njrat {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "identifies njRat version 0.7d"

    strings:
        $str_1 = "[TAP]" wide
        $str_2 = "[ENTER]" wide
        $str_3 = "cmd.exe /C Y /N /D Y /T 1 & Del" wide
        $str_4 = "Download ERROR" wide
        $str_5 = "Executed As" wide
        $str_6 = "Updating To" wide

    condition:
        uint16(0) == 0x5A4D and 
        all of them 
}

rule win_njrat_2 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "identifies njRat vesrion 0.7 Golden"

    strings:
        $a = "Njrat 0.7 Golden By Hassan Amiri" wide

    condition:
        uint16(0) == 0x5A4D and 
        all of them
}

rule win_njrat_3 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "identifies njRat"

    strings:
        $str_var_1 = "HOST" ascii
        $str_var_2 = "Port" ascii
        $str_var_3 = "Botid" ascii
        $str_var_4 = "Version" ascii
        $str_var_5 = "InstallDir" ascii
        $str_var_6 = "InstallPath" ascii
        $str_var_7 = "InstallFname" ascii
        $str_var_8 = "Reg_Key" ascii
        $str_var_9 = "Start_Up" ascii
        $str_var_10 = "PasswordSocket" ascii
        $str_var_11 = "HOST2" ascii

        $str_av_1 = "NOD32" wide
        $str_av_2 = "AVG" wide
        $str_av_3 = "Avira" wide
        $str_av_4 = "AhnLab-V3" wide
        $str_av_5 = "BitDefender" wide
        $str_av_6 = "ByteHero" wide
        $str_av_7 = "ClamAV" wide
        $str_av_8 = "F-Prot" wide
        $str_av_9 = "F-Secure" wide
        $str_av_10 = "GData" wide
        $str_av_11 = "Jiangmin" wide
        $str_av_12 = "Kaspersky" wide
        $str_av_13 = "McAfee" wide
        $str_av_14 = "Microsoft Security Essentials" wide
        $str_av_15 = "Windows Defender" wide
        $str_av_16 = "Norman" wide
        $str_av_17 = "nProtect" wide
        $str_av_18 = "Panda" wide
        $str_av_19 = "Prevx" wide
        $str_av_20 = "Sophos" wide
        $str_av_21 = "Sophos" wide
        $str_av_22 = "SUPERAntiSpyware" wide
        $str_av_23 = "Symantec" wide
        $str_av_24 = "TheHacker" wide
        $str_av_25 = "TrendMicro" wide
        $str_av_26 = "VBA32" wide
        $str_av_27 = "VIPRE" wide
        $str_av_28 = "ViRobot" wide
        $str_av_29 = "VBA32" wide
        $str_av_30 = "VirusBuster" wide

        $str_func_1 = "njLogger" ascii
        $str_func_2 = "SetWindowsHookEx" ascii
        $str_func_3 = "CallNextHookEx" ascii
        $str_func_4 = "VKCodeToUnicode" ascii
        $str_func_5 = "GetWindowThreadProcessId" ascii
        $str_func_6 = "MapVirtualKey" ascii

    condition:
        uint16(0) == 0x5A4D and 
        10 of ($str_var_*) and 
        28 of ($str_av_*) and 
        4 of ($str_func_*)
}

rule win_njrat_x7 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "identifies njRat"

    strings:
        $str_keys_1 = "[TAP]" wide
        $str_keys_2 = "[ENTER]" wide

        $str_func_1 = "VKCodeToUnicode" ascii
        $str_func_2 = "MapVirtualKey" ascii
        $str_func_3 = "capGetDriverDescriptionA" ascii

        $str_var_1 = "LastAS" ascii
        $str_var_2 = "LastAV" ascii
        $str_var_3 = "TempoSleep" ascii
        $str_var_4 = "DownloadHostOrNotURL" ascii
        $str_var_5 = "CopyMyFileDir" ascii

    condition:
        uint16(0) == 0x5A4D and 
        all of them 
}