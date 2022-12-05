rule win_wshrat_1 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "identifies WSHRAT"

    strings:
        $str_a_1 = "WSHRat Plugin" ascii
        $str_a_2 = "TotalMouseMoves" ascii
        
        $str_b_1 = "TotalKeyboardClick" ascii
        $str_b_2 = "TotalMouseMoves" ascii
        $str_b_3 = "TotalMouseClick" ascii
        $str_b_4 = "SessionKeyboardClick" ascii
        $str_b_5 = "SessionMouseMoves" ascii
        $str_b_6 = "SessionMouseClick" ascii

        $str_c_1 = "/open-keylogger" wide

    condition:
        uint16(0) == 0x5A4D and 
        all of ($str_a_*) and 
        4 of ($str_b_*) and 
        all of ($str_c_*)
}