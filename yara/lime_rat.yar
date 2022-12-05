rule win_limerat_j1 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.1"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "detects the lime rat"
        hash        = "2a0575b66a700edb40a07434895bf7a9"
        malpedia_family = "win.limerat"

    strings:
        $str_1 = "Y21kLmV4ZSAvYyBwaW5nIDAgLW4gMiAmIGRlbCA=" wide
        $str_2 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin" wide
        $str_3 = "Minning..." wide
        $str_4 = "--donate-level=" wide

    condition:
        uint16(0) == 0x5A4D and 
        3 of them
}
